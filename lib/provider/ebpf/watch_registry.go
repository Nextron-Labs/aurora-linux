package ebpf

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
)

// Inode-based watches for the security-hook monitor (audit_hooks.c).
//
// Like auditd's "-w", a watch is attached to the inode of a file, so every
// spelling of its path (symlinks, "//", "..", /proc/self/fd, bind mounts)
// hits it. Directories in which a watched file may be created get a
// directory watch so creations, renames and links into them are seen.

const (
	wFile      uint8 = 1
	wDir       uint8 = 2
	wRecursive uint8 = 4 // RECURSIVE_DEPTH (4) levels below the directory

	nameKeyBytes = 32
	// Recursive "dir/*" watches stop at this depth below the directory.
	maxRecursiveDepth = 4
	// Upper bound of watched inodes (map size in audit_hooks.c is 32768).
	maxWatchedInodes = 30000
)

// hookInodeKey mirrors struct inode_key in audit_hooks.c.
type hookInodeKey struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

// hookWatchVal mirrors struct watch_val in audit_hooks.c.
type hookWatchVal struct {
	ID    uint32
	Flags uint8
	Perms uint8
	Pad   uint16
}

type hookNameKey struct {
	Name [nameKeyBytes]byte
}

type watchEntry struct {
	path  string // spelling used in records (as written in the watch rule)
	flags uint8
	perms accessPerm
}

// pathAlias maps a canonical directory back to the spelling the rules use
// (e.g. /run -> /var/run).
type pathAlias struct {
	canonical, literal string
}

type watchRegistry struct {
	rules *watchSet

	mu      sync.RWMutex
	entries map[uint32]watchEntry
	ids     map[hookInodeKey]uint32
	nextID  uint32
	aliases []pathAlias

	inodes *ebpf.Map // nil in tests
	names  *ebpf.Map

	refresh chan struct{}
}

func newWatchRegistry(rules *watchSet, inodes, names *ebpf.Map) *watchRegistry {
	return &watchRegistry{
		rules:   rules,
		entries: map[uint32]watchEntry{},
		ids:     map[hookInodeKey]uint32{},
		nextID:  1,
		inodes:  inodes,
		names:   names,
		refresh: make(chan struct{}, 1),
	}
}

// entry returns the watch entry for an id reported by the kernel.
func (r *watchRegistry) entry(id uint32) (watchEntry, bool) {
	if r == nil || id == 0 {
		return watchEntry{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	return e, ok
}

// translate rewrites a canonical kernel path to the spelling used by the
// watch rules (e.g. /run/x.pid -> /var/run/x.pid).
func (r *watchRegistry) translate(p string) string {
	if r == nil {
		return p
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.aliases {
		if p == a.canonical {
			return a.literal
		}
		if strings.HasPrefix(p, a.canonical+"/") {
			return a.literal + p[len(a.canonical):]
		}
	}
	return p
}

// requestRefresh schedules an asynchronous re-sync (e.g. after a watched file
// or directory was created).
func (r *watchRegistry) requestRefresh() {
	if r == nil {
		return
	}
	select {
	case r.refresh <- struct{}{}:
	default:
	}
}

type watchTarget struct {
	path  string
	flags uint8
	perms accessPerm
}

// targets expands all rules to existing files and creation directories.
func (r *watchRegistry) targets() (out []watchTarget, aliases []pathAlias, names []string) {
	seenAlias := map[string]bool{}
	addAlias := func(dir string) {
		canon, err := filepath.EvalSymlinks(dir)
		if err != nil || canon == dir || seenAlias[canon] {
			return
		}
		seenAlias[canon] = true
		aliases = append(aliases, pathAlias{canonical: canon, literal: dir})
	}
	nameSet := map[string]bool{}

	for _, rule := range r.rules.rules {
		files, dirs, recDirs := expandPattern(rule.pattern)
		for _, f := range files {
			out = append(out, watchTarget{path: f, flags: wFile, perms: rule.perms})
			addAlias(path.Dir(f))
		}
		if rule.perms&permWrite != 0 {
			for _, d := range dirs {
				out = append(out, watchTarget{path: d, flags: wDir, perms: rule.perms})
				addAlias(d)
			}
			for _, d := range recDirs {
				out = append(out, watchTarget{path: d, flags: wDir | wRecursive, perms: rule.perms})
				addAlias(d)
			}
		}
		leaf := path.Base(rule.pattern)
		if !strings.Contains(leaf, "*") && len(leaf) < nameKeyBytes && rule.perms&permWrite != 0 {
			nameSet[leaf] = true
		}
	}
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)
	// Longest canonical prefix first.
	sort.Slice(aliases, func(i, j int) bool { return len(aliases[i].canonical) > len(aliases[j].canonical) })
	return out, aliases, names
}

// sync re-expands the rules and updates the kernel maps.
func (r *watchRegistry) sync() {
	targets, aliases, names := r.targets()
	mounts := loadMountTable()

	want := map[hookInodeKey]hookWatchVal{}
	wantEntry := map[hookInodeKey]watchEntry{}
	for _, t := range targets {
		if len(want) >= maxWatchedInodes {
			log.WithField("limit", maxWatchedInodes).Warn("Watch inode limit reached; some watches are not registered")
			break
		}
		key, ok := inodeKeyFor(t.path, mounts)
		if !ok {
			continue
		}
		v := want[key]
		v.Flags |= t.flags
		v.Perms |= uint8(t.perms)
		want[key] = v
		e, exists := wantEntry[key]
		if !exists || (e.flags&wFile == 0 && t.flags&wFile != 0) {
			e.path = t.path // prefer a file spelling over a directory one
		}
		e.flags |= t.flags
		e.perms |= t.perms
		wantEntry[key] = e
	}

	r.mu.Lock()
	r.aliases = aliases
	for key, v := range want {
		id, ok := r.ids[key]
		if !ok {
			id = r.nextID
			r.nextID++
			r.ids[key] = id
		}
		v.ID = id
		r.entries[id] = wantEntry[key]
		if r.inodes != nil {
			if err := r.inodes.Put(key, v); err != nil {
				log.WithError(err).WithField("path", wantEntry[key].path).Debug("Registering watch inode failed")
			}
		}
	}
	for key, id := range r.ids {
		if _, ok := want[key]; ok {
			continue
		}
		delete(r.ids, key)
		delete(r.entries, id)
		if r.inodes != nil {
			_ = r.inodes.Delete(key)
		}
	}
	r.mu.Unlock()

	if r.names != nil {
		for _, n := range names {
			var k hookNameKey
			copy(k.Name[:], n)
			_ = r.names.Put(k, uint8(1))
		}
	}
}

// expandPattern returns the existing files a watch pattern covers, the
// directories in which matching files could be created, and directories that
// need a recursive watch (the tree under "dir/*", or the nearest existing
// ancestor of a directory that does not exist yet). '*' in the leaf matches
// within a directory; a leaf of exactly "*" covers the directory
// recursively; a leading "*/" means any home directory (/root, /home/*).
func expandPattern(pat string) (files, dirs, recDirs []string) {
	if strings.HasPrefix(pat, "*/") {
		for _, root := range []string{"/root", "/home/*"} {
			f, d, r := expandPattern(root + pat[1:])
			files = append(files, f...)
			dirs = append(dirs, d...)
			recDirs = append(recDirs, r...)
		}
		return files, dirs, recDirs
	}
	dirPat, leaf := path.Dir(pat), path.Base(pat)
	concrete := expandDirs(dirPat)
	if len(concrete) == 0 {
		// The directory does not exist (yet): watch its nearest existing
		// ancestor recursively so creations below it are seen at once.
		if a := nearestExistingAncestor(dirPat); a != "" {
			recDirs = append(recDirs, a)
		}
		return files, dirs, recDirs
	}
	for _, d := range concrete {
		if leaf == "*" {
			var sub []string
			walkRecursive(d, 0, &files, &sub)
			recDirs = append(recDirs, sub...)
			continue
		}
		dirs = append(dirs, d)
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if ok, _ := path.Match(leaf, e.Name()); ok {
				files = append(files, path.Join(d, e.Name()))
			}
		}
	}
	return files, dirs, recDirs
}

func walkRecursive(d string, depth int, files, dirs *[]string) {
	*dirs = append(*dirs, d)
	if depth >= maxRecursiveDepth {
		return
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := path.Join(d, e.Name())
		if e.IsDir() {
			walkRecursive(p, depth+1, files, dirs)
			continue
		}
		*files = append(*files, p)
	}
}

// expandDirs resolves a directory pattern whose components may contain '*'.
func expandDirs(dirPat string) []string {
	cur := []string{"/"}
	for _, comp := range strings.Split(strings.Trim(dirPat, "/"), "/") {
		if comp == "" {
			continue
		}
		var next []string
		for _, base := range cur {
			if !strings.Contains(comp, "*") {
				p := path.Join(base, comp)
				if st, err := os.Stat(p); err == nil && st.IsDir() {
					next = append(next, p)
				}
				continue
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if ok, _ := path.Match(comp, e.Name()); !ok {
					continue
				}
				p := path.Join(base, e.Name())
				if st, err := os.Stat(p); err == nil && st.IsDir() {
					next = append(next, p)
				}
			}
		}
		cur = next
		if len(cur) == 0 {
			return nil
		}
	}
	return cur
}

func nearestExistingAncestor(p string) string {
	if i := strings.IndexByte(p, '*'); i >= 0 {
		p = path.Dir(p[:i] + "x")
	}
	for p != "/" && p != "." && p != "" {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
		p = path.Dir(p)
	}
	return ""
}

// ---------------------------------------------------------------------------
// device numbers: the kernel compares inode->i_sb->s_dev, which is what
// /proc/self/mountinfo shows (stat's st_dev differs on btrfs subvolumes).
// ---------------------------------------------------------------------------

type mountEntry struct {
	point string
	dev   uint32
}

type mountTable []mountEntry

func loadMountTable() mountTable {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseMountInfo(bufio.NewScanner(f))
}

func parseMountInfo(sc *bufio.Scanner) mountTable {
	var mt mountTable
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mm := strings.SplitN(fields[2], ":", 2)
		if len(mm) != 2 {
			continue
		}
		maj, err1 := strconv.ParseUint(mm[0], 10, 32)
		min, err2 := strconv.ParseUint(mm[1], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		mt = append(mt, mountEntry{point: unescapeMountPath(fields[4]), dev: uint32(maj<<20 | min)})
	}
	// Longest mount point first; for equal points the later (top) mount wins.
	sort.SliceStable(mt, func(i, j int) bool { return len(mt[i].point) > len(mt[j].point) })
	return mt
}

// unescapeMountPath decodes the octal escapes (\040 etc.) in mountinfo.
func unescapeMountPath(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (mt mountTable) devFor(p string) (uint32, bool) {
	var best *mountEntry
	for i := range mt {
		m := &mt[i]
		if p == m.point || m.point == "/" || strings.HasPrefix(p, m.point+"/") {
			if best == nil || len(m.point) >= len(best.point) { // ">=": the top-most of stacked mounts wins
				best = m
			}
		}
	}
	if best == nil {
		return 0, false
	}
	return best.dev, true
}

func inodeKeyFor(p string, mt mountTable) (hookInodeKey, bool) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return hookInodeKey{}, false
	}
	st, err := os.Stat(real)
	if err != nil {
		return hookInodeKey{}, false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return hookInodeKey{}, false
	}
	dev, ok := mt.devFor(real)
	if !ok {
		return hookInodeKey{}, false
	}
	return hookInodeKey{Ino: sys.Ino, Dev: dev}, true
}
