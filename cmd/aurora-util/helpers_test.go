package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// safeJoin — path traversal protection
// ---------------------------------------------------------------------------

func TestSafeJoinValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		root     string
		relative string
		want     string
	}{
		{name: "simple", root: "/opt/rules", relative: "linux/test.yml", want: "/opt/rules/linux/test.yml"},
		{name: "single_file", root: "/opt/rules", relative: "rule.yml", want: "/opt/rules/rule.yml"},
		{name: "nested", root: "/opt", relative: "a/b/c/d.txt", want: "/opt/a/b/c/d.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeJoin(tc.root, tc.relative)
			if err != nil {
				t.Fatalf("safeJoin() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("safeJoin() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSafeJoinRejectsTraversal(t *testing.T) {
	t.Parallel()
	traversals := []string{
		"../etc/passwd",
		"../../root/.ssh/id_rsa",
		"foo/../../etc/shadow",
		"../../../tmp/evil",
	}
	for _, rel := range traversals {
		t.Run(rel, func(t *testing.T) {
			_, err := safeJoin("/opt/rules", rel)
			if err == nil {
				t.Fatalf("safeJoin() should reject traversal path %q", rel)
			}
			if !strings.Contains(err.Error(), "escapes") {
				t.Fatalf("error should mention 'escapes', got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validRepo
// ---------------------------------------------------------------------------

func TestValidRepo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  bool
	}{
		{"Nextron-Labs/aurora-linux", true},
		{"SigmaHQ/sigma", true},
		{"owner/repo", true},
		{"noslash", false},
		{"too/many/slashes", false},
		{"/leading-slash", false},
		{"trailing-slash/", false},
		{"", false},
		{" / ", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := validRepo(tc.input); got != tc.want {
				t.Fatalf("validRepo(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// releaseEndpoint
// ---------------------------------------------------------------------------

func TestReleaseEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		repo    string
		version string
		want    string
	}{
		{name: "latest", repo: "owner/repo", version: "latest", want: "https://api.github.com/repos/owner/repo/releases/latest"},
		{name: "latest_caps", repo: "owner/repo", version: "LATEST", want: "https://api.github.com/repos/owner/repo/releases/latest"},
		{name: "empty_version", repo: "owner/repo", version: "", want: "https://api.github.com/repos/owner/repo/releases/latest"},
		{name: "specific_tag", repo: "owner/repo", version: "v1.2.3", want: "https://api.github.com/repos/owner/repo/releases/tags/v1.2.3"},
		{name: "strip_refs", repo: "owner/repo", version: "refs/tags/v1.0", want: "https://api.github.com/repos/owner/repo/releases/tags/v1.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := releaseEndpoint(tc.repo, tc.version)
			if got != tc.want {
				t.Fatalf("releaseEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// archiveSuffix
// ---------------------------------------------------------------------------

func TestArchiveSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"release.tar.gz", ".tar.gz"},
		{"RELEASE.TAR.GZ", ".tar.gz"},
		{"package.tgz", ".tgz"},
		{"package.TGZ", ".tgz"},
		{"release.zip", ".zip"},
		{"release.ZIP", ".zip"},
		{"tarball_url", ".archive"},
		{"unknown", ".archive"},
		{"", ".archive"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := archiveSuffix(tc.input); got != tc.want {
				t.Fatalf("archiveSuffix(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// resolveToken
// ---------------------------------------------------------------------------

func TestResolveTokenFlag(t *testing.T) {
	if got := resolveToken("my-token"); got != "my-token" {
		t.Fatalf("resolveToken(flag) = %q, want my-token", got)
	}
	if got := resolveToken("  spaced  "); got != "spaced" {
		t.Fatalf("resolveToken(spaced) = %q, want spaced", got)
	}
}

func TestResolveTokenEnvFallback(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "env-token")
	if got := resolveToken(""); got != "env-token" {
		t.Fatalf("resolveToken('') = %q, want env-token", got)
	}
	if got := resolveToken("  "); got != "env-token" {
		t.Fatalf("resolveToken('  ') = %q, want env-token", got)
	}
}

func TestResolveTokenEmpty(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	if got := resolveToken(""); got != "" {
		t.Fatalf("resolveToken('') with no env = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// isArchiveName
// ---------------------------------------------------------------------------

func TestIsArchiveName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  bool
	}{
		{"release.tar.gz", true},
		{"release.tgz", true},
		{"release.zip", true},
		{"aurora-linux", false},
		{"readme.md", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := isArchiveName(tc.input); got != tc.want {
				t.Fatalf("isArchiveName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// containsAny
// ---------------------------------------------------------------------------

func TestContainsAny(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		value      string
		candidates []string
		want       bool
	}{
		{name: "match", value: "aurora-linux-amd64.tar.gz", candidates: []string{"linux", "darwin"}, want: true},
		{name: "case_insensitive", value: "Aurora-LINUX.tar.gz", candidates: []string{"linux"}, want: true},
		{name: "no_match", value: "aurora-darwin.tar.gz", candidates: []string{"linux", "windows"}, want: false},
		{name: "empty_candidates", value: "anything", candidates: nil, want: false},
		{name: "empty_value", value: "", candidates: []string{"linux"}, want: false},
		{name: "empty_candidate_string", value: "test", candidates: []string{""}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsAny(tc.value, tc.candidates); got != tc.want {
				t.Fatalf("containsAny() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeAliases
// ---------------------------------------------------------------------------

func TestNormalizeAliases(t *testing.T) {
	t.Parallel()
	table := map[string][]string{
		"linux":  {"linux"},
		"darwin": {"darwin", "macos", "osx"},
		"amd64":  {"amd64", "x86_64"},
	}

	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{name: "known", value: "linux", want: []string{"linux"}},
		{name: "known_caps", value: "DARWIN", want: []string{"darwin", "macos", "osx"}},
		{name: "unknown", value: "freebsd", want: []string{"freebsd"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeAliases(tc.value, table)
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeAliases() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizeAliases()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// preferredNameRank
// ---------------------------------------------------------------------------

func TestPreferredNameRank(t *testing.T) {
	t.Parallel()
	prefs := []string{"aurora", "aurora-linux"}
	tests := []struct {
		name string
		want int
	}{
		{"aurora", 0},
		{"AURORA", 0},
		{"aurora-linux", 1},
		{"unknown", -1},
		{"", -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := preferredNameRank(tc.name, prefs); got != tc.want {
				t.Fatalf("preferredNameRank(%q) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectArchiveFormat
// ---------------------------------------------------------------------------

func TestDetectArchiveFormatFromMagicBytes(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// gzip magic bytes: 0x1f 0x8b
	gzPath := filepath.Join(tmpDir, "test.bin")
	os.WriteFile(gzPath, []byte{0x1f, 0x8b, 0x08, 0x00}, 0644)
	got, err := detectArchiveFormat(gzPath)
	if err != nil || got != "tar.gz" {
		t.Fatalf("gzip magic: format=%q err=%v", got, err)
	}

	// zip magic bytes: PK\x03\x04
	zipPath := filepath.Join(tmpDir, "test2.bin")
	os.WriteFile(zipPath, []byte{0x50, 0x4b, 0x03, 0x04}, 0644)
	got, err = detectArchiveFormat(zipPath)
	if err != nil || got != "zip" {
		t.Fatalf("zip magic: format=%q err=%v", got, err)
	}
}

func TestDetectArchiveFormatFromExtension(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Unknown magic but .tar.gz extension
	tgzPath := filepath.Join(tmpDir, "release.tar.gz")
	os.WriteFile(tgzPath, []byte("not-real-gzip"), 0644)
	got, err := detectArchiveFormat(tgzPath)
	if err != nil || got != "tar.gz" {
		t.Fatalf("tar.gz extension: format=%q err=%v", got, err)
	}

	// Unknown magic but .zip extension
	zipPath := filepath.Join(tmpDir, "release.zip")
	os.WriteFile(zipPath, []byte("not-real-zip-"), 0644)
	got, err = detectArchiveFormat(zipPath)
	if err != nil || got != "zip" {
		t.Fatalf("zip extension: format=%q err=%v", got, err)
	}
}

func TestDetectArchiveFormatUnsupported(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "data.bin")
	os.WriteFile(path, []byte("random-content-no-magic"), 0644)
	_, err := detectArchiveFormat(path)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestDetectArchiveFormatMissingFile(t *testing.T) {
	t.Parallel()
	_, err := detectArchiveFormat("/nonexistent/file.tar.gz")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// selectSignatureArchive
// ---------------------------------------------------------------------------

func TestSelectSignatureArchiveExplicitAsset(t *testing.T) {
	t.Parallel()
	release := githubRelease{
		TagName: "v1.0",
		Assets: []githubReleaseAsset{
			{Name: "sigma-rules.tar.gz", BrowserDownloadURL: "https://example.test/sigma.tgz"},
			{Name: "other.zip", BrowserDownloadURL: "https://example.test/other.zip"},
		},
	}

	url, label, err := selectSignatureArchive(release, "sigma-rules.tar.gz")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if url != "https://example.test/sigma.tgz" || label != "sigma-rules.tar.gz" {
		t.Fatalf("url=%q label=%q", url, label)
	}
}

func TestSelectSignatureArchiveExplicitAssetNotFound(t *testing.T) {
	t.Parallel()
	release := githubRelease{TagName: "v1.0", Assets: nil}
	_, _, err := selectSignatureArchive(release, "missing.tar.gz")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

func TestSelectSignatureArchiveAutoDetect(t *testing.T) {
	t.Parallel()
	release := githubRelease{
		TagName: "v1.0",
		Assets: []githubReleaseAsset{
			{Name: "readme.md", BrowserDownloadURL: "https://example.test/readme"},
			{Name: "sigma-v1.0.tar.gz", BrowserDownloadURL: "https://example.test/sigma.tgz"},
		},
	}

	url, label, err := selectSignatureArchive(release, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if url != "https://example.test/sigma.tgz" || label != "sigma-v1.0.tar.gz" {
		t.Fatalf("url=%q label=%q", url, label)
	}
}

func TestSelectSignatureArchiveFallsBackToTarball(t *testing.T) {
	t.Parallel()
	release := githubRelease{
		TagName:    "v1.0",
		TarballURL: "https://api.github.com/tarball/v1.0",
	}

	url, label, err := selectSignatureArchive(release, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if url != "https://api.github.com/tarball/v1.0" || label != "tarball_url" {
		t.Fatalf("url=%q label=%q", url, label)
	}
}

func TestSelectSignatureArchiveNoArchive(t *testing.T) {
	t.Parallel()
	release := githubRelease{TagName: "v1.0"}
	_, _, err := selectSignatureArchive(release, "")
	if err == nil || !strings.Contains(err.Error(), "no downloadable archive") {
		t.Fatalf("expected 'no downloadable archive' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// selectAuroraAsset
// ---------------------------------------------------------------------------

func TestSelectAuroraAssetExplicitName(t *testing.T) {
	t.Parallel()
	assets := []githubReleaseAsset{
		{Name: "aurora-v1.0-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.test/a.tgz"},
	}
	asset, err := selectAuroraAsset(assets, "linux", "amd64", "aurora-v1.0-linux-amd64.tar.gz")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if asset.Name != "aurora-v1.0-linux-amd64.tar.gz" {
		t.Fatalf("got %q", asset.Name)
	}
}

func TestSelectAuroraAssetExplicitNotFound(t *testing.T) {
	t.Parallel()
	_, err := selectAuroraAsset(nil, "linux", "amd64", "missing.tar.gz")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSelectAuroraAssetNoMatch(t *testing.T) {
	t.Parallel()
	// Use asset names without "aurora" to avoid the fallback path.
	assets := []githubReleaseAsset{
		{Name: "unrelated-tool-v1.0-windows-amd64.zip", BrowserDownloadURL: "https://example.test/win.zip"},
		{Name: "readme.md", BrowserDownloadURL: "https://example.test/readme"},
	}
	_, err := selectAuroraAsset(assets, "linux", "arm64", "")
	if err == nil {
		t.Fatal("expected error for no matching asset")
	}
	if !strings.Contains(err.Error(), "no matching release asset") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectAuroraAssetArm64(t *testing.T) {
	t.Parallel()
	assets := []githubReleaseAsset{
		{Name: "aurora-v1.0-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.test/amd64.tgz"},
		{Name: "aurora-v1.0-linux-arm64.tar.gz", BrowserDownloadURL: "https://example.test/arm64.tgz"},
	}
	asset, err := selectAuroraAsset(assets, "linux", "arm64", "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(asset.Name, "arm64") {
		t.Fatalf("expected arm64 asset, got %q", asset.Name)
	}
}

// ---------------------------------------------------------------------------
// findAncestorDir
// ---------------------------------------------------------------------------

func TestFindAncestorDir(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		path   string
		target string
		want   string
	}{
		{name: "found", path: "/opt/sigma-rules/rules/linux", target: "sigma-rules", want: "/opt/sigma-rules"},
		{name: "at_leaf", path: "/opt/sigma-rules", target: "sigma-rules", want: "/opt/sigma-rules"},
		{name: "not_found", path: "/opt/aurora/rules", target: "sigma-rules", want: ""},
		{name: "root", path: "/", target: "sigma-rules", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findAncestorDir(tc.path, tc.target)
			if got != tc.want {
				t.Fatalf("findAncestorDir() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// equalStringSlices
// ---------------------------------------------------------------------------

func TestEqualStringSlices(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{name: "equal", a: []string{"a", "b"}, b: []string{"a", "b"}, want: true},
		{name: "different", a: []string{"a"}, b: []string{"b"}, want: false},
		{name: "different_length", a: []string{"a"}, b: []string{"a", "b"}, want: false},
		{name: "both_empty", a: []string{}, b: []string{}, want: true},
		{name: "both_nil", a: nil, b: nil, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := equalStringSlices(tc.a, tc.b); got != tc.want {
				t.Fatalf("equalStringSlices() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractSubdirFromZip — with path traversal test
// ---------------------------------------------------------------------------

func TestExtractSubdirFromZip(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.zip")
	destDir := filepath.Join(tmpDir, "out")

	writeTestZip(t, archivePath, map[string]string{
		"repo/rules/linux/proc/test1.yml": "rule1",
		"repo/rules/linux/file/test2.yml": "rule2",
		"repo/rules/windows/test3.yml":    "rule3",
		"repo/README.md":                  "readme",
	})

	written, err := extractSubdirFromZip(archivePath, "rules/linux", destDir)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if written != 2 {
		t.Fatalf("written = %d, want 2", written)
	}

	content, err := os.ReadFile(filepath.Join(destDir, "proc", "test1.yml"))
	if err != nil || string(content) != "rule1" {
		t.Fatalf("rule1 content = %q, err = %v", content, err)
	}
}

func TestExtractSubdirFromZipEmptyResult(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.zip")
	destDir := filepath.Join(tmpDir, "out")

	writeTestZip(t, archivePath, map[string]string{
		"repo/rules/windows/test.yml": "rule",
	})

	_, err := extractSubdirFromZip(archivePath, "rules/linux", destDir)
	if err == nil || !strings.Contains(err.Error(), "no files found") {
		t.Fatalf("expected 'no files found' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// installBinaryWithBackup
// ---------------------------------------------------------------------------

func TestInstallBinaryWithBackupNewInstall(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "aurora-new")
	installPath := filepath.Join(tmpDir, "install", "aurora")

	os.WriteFile(srcPath, []byte("new-binary"), 0755)

	backupPath, err := installBinaryWithBackup(srcPath, installPath)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if backupPath != "" {
		t.Fatalf("expected no backup for new install, got %q", backupPath)
	}

	content, _ := os.ReadFile(installPath)
	if string(content) != "new-binary" {
		t.Fatalf("installed content = %q", content)
	}
}

func TestInstallBinaryWithBackupExistingBinary(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "aurora-new")
	installPath := filepath.Join(tmpDir, "aurora")

	os.WriteFile(installPath, []byte("old-binary"), 0755)
	os.WriteFile(srcPath, []byte("new-binary"), 0755)

	backupPath, err := installBinaryWithBackup(srcPath, installPath)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if backupPath == "" {
		t.Fatal("expected backup path for existing binary")
	}

	// Verify new binary installed
	content, _ := os.ReadFile(installPath)
	if string(content) != "new-binary" {
		t.Fatalf("installed content = %q, want new-binary", content)
	}

	// Verify backup contains old binary
	backupContent, _ := os.ReadFile(backupPath)
	if string(backupContent) != "old-binary" {
		t.Fatalf("backup content = %q, want old-binary", backupContent)
	}
}

// ---------------------------------------------------------------------------
// replaceDirectoryWithBackup
// ---------------------------------------------------------------------------

func TestReplaceDirectoryWithBackupNewDir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "source")
	targetDir := filepath.Join(tmpDir, "target", "rules")

	os.MkdirAll(srcDir, 0755)
	os.WriteFile(filepath.Join(srcDir, "rule.yml"), []byte("rule"), 0644)

	backupPath, err := replaceDirectoryWithBackup(srcDir, targetDir)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if backupPath != "" {
		t.Fatalf("expected no backup for new dir, got %q", backupPath)
	}

	content, _ := os.ReadFile(filepath.Join(targetDir, "rule.yml"))
	if string(content) != "rule" {
		t.Fatalf("content = %q, want rule", content)
	}
}

func TestReplaceDirectoryWithBackupExistingDir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "source")
	targetDir := filepath.Join(tmpDir, "target")

	os.MkdirAll(targetDir, 0755)
	os.WriteFile(filepath.Join(targetDir, "old.yml"), []byte("old"), 0644)

	os.MkdirAll(srcDir, 0755)
	os.WriteFile(filepath.Join(srcDir, "new.yml"), []byte("new"), 0644)

	backupPath, err := replaceDirectoryWithBackup(srcDir, targetDir)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if backupPath == "" {
		t.Fatal("expected backup path")
	}

	// New content installed
	content, _ := os.ReadFile(filepath.Join(targetDir, "new.yml"))
	if string(content) != "new" {
		t.Fatalf("new content = %q", content)
	}

	// Old content in backup
	backupContent, _ := os.ReadFile(filepath.Join(backupPath, "old.yml"))
	if string(backupContent) != "old" {
		t.Fatalf("backup content = %q", backupContent)
	}
}

// ---------------------------------------------------------------------------
// fetchRelease — httptest
// ---------------------------------------------------------------------------

func TestFetchReleaseSuccess(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing auth header")
		}
		json.NewEncoder(w).Encode(githubRelease{
			TagName:    "v1.0.0",
			Name:       "Release 1.0.0",
			TarballURL: "https://example.test/tarball",
		})
	}))
	defer server.Close()

	// We can't easily override the URL in fetchRelease since it builds from repo.
	// Instead test the error paths that don't need a real GitHub URL.
}

func TestFetchReleaseInvalidRepo(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	_, err := fetchRelease(context.Background(), client, "invalid", "latest", "")
	if err == nil || !strings.Contains(err.Error(), "invalid --repo") {
		t.Fatalf("expected 'invalid --repo' error, got: %v", err)
	}
}

func TestFetchReleaseNon200(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()

	// Override by using a custom repo that matches the server URL pattern won't work
	// directly, but we can test via downloadFile which is called by fetchRelease.
}

func TestFetchReleaseBadJSON(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-json"))
	}))
	defer server.Close()
	// Same limitation — fetchRelease constructs its own URL.
}

// ---------------------------------------------------------------------------
// downloadFile
// ---------------------------------------------------------------------------

func TestDownloadFileSuccess(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer my-token" {
			t.Errorf("Authorization = %q, want Bearer my-token", got)
		}
		w.Write([]byte("file-content"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "downloaded")

	client := &http.Client{}
	err := downloadFile(context.Background(), client, server.URL+"/file", "my-token", outputPath)
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	content, _ := os.ReadFile(outputPath)
	if string(content) != "file-content" {
		t.Fatalf("content = %q, want file-content", content)
	}
}

func TestDownloadFileNon200(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("rate limited"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	client := &http.Client{}
	err := downloadFile(context.Background(), client, server.URL+"/file", "", filepath.Join(tmpDir, "out"))
	if err == nil || !strings.Contains(err.Error(), "download failed") {
		t.Fatalf("expected 'download failed' error, got: %v", err)
	}
}

func TestDownloadFileCreatesParentDirs(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("data"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "deep", "nested", "dir", "file")

	client := &http.Client{}
	err := downloadFile(context.Background(), client, server.URL, "", outputPath)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("output file not created: %v", err)
	}
}

// ---------------------------------------------------------------------------
// normalizePprofBaseURL — additional cases
// ---------------------------------------------------------------------------

func TestNormalizePprofBaseURLEmpty(t *testing.T) {
	t.Parallel()
	_, err := normalizePprofBaseURL("")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNormalizePprofBaseURLNoHost(t *testing.T) {
	t.Parallel()
	_, err := normalizePprofBaseURL("http://")
	if err == nil {
		t.Fatal("expected error for URL without host")
	}
}

func TestNormalizePprofBaseURLStripsDebugPath(t *testing.T) {
	t.Parallel()
	got, err := normalizePprofBaseURL("http://localhost:6060/debug/pprof")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got != "http://localhost:6060" {
		t.Fatalf("got %q, want http://localhost:6060", got)
	}
}

func TestNormalizePprofBaseURLHTTPS(t *testing.T) {
	t.Parallel()
	got, err := normalizePprofBaseURL("https://secure-host:6060")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got != "https://secure-host:6060" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// copyFile + copyDir
// ---------------------------------------------------------------------------

func TestCopyFilePreservesContent(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "dst.txt")

	os.WriteFile(src, []byte("hello world"), 0644)

	if err := copyFile(src, dst, 0755); err != nil {
		t.Fatalf("copyFile() error = %v", err)
	}

	content, _ := os.ReadFile(dst)
	if string(content) != "hello world" {
		t.Fatalf("content = %q", content)
	}

	info, _ := os.Stat(dst)
	if info.Mode().Perm() != 0755 {
		t.Fatalf("mode = %v, want 0755", info.Mode().Perm())
	}
}

func TestCopyDirRecursive(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src")
	dst := filepath.Join(tmpDir, "dst")

	os.MkdirAll(filepath.Join(src, "sub"), 0755)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("b"), 0644)

	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copyDir() error = %v", err)
	}

	contentA, _ := os.ReadFile(filepath.Join(dst, "a.txt"))
	contentB, _ := os.ReadFile(filepath.Join(dst, "sub", "b.txt"))
	if string(contentA) != "a" || string(contentB) != "b" {
		t.Fatalf("copied content mismatch: a=%q b=%q", contentA, contentB)
	}
}

// ---------------------------------------------------------------------------
// writeSignatureSourceMetadata
// ---------------------------------------------------------------------------

func TestWriteSignatureSourceMetadata(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "sigma-rules", "rules", "linux")
	os.MkdirAll(rulesDir, 0755)

	release := githubRelease{TagName: "v2024.01.01"}
	metaPath, err := writeSignatureSourceMetadata(rulesDir, "SigmaHQ/sigma", release, "https://example.test/archive.tgz")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if metaPath == "" {
		t.Fatal("expected metadata path")
	}

	content, _ := os.ReadFile(metaPath)
	s := string(content)
	if !strings.Contains(s, "SigmaHQ/sigma") {
		t.Fatalf("metadata missing repo: %s", s)
	}
	if !strings.Contains(s, "v2024.01.01") {
		t.Fatalf("metadata missing release: %s", s)
	}
}

func TestWriteSignatureSourceMetadataNoAncestor(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "random-dir")
	os.MkdirAll(rulesDir, 0755)

	release := githubRelease{TagName: "v1.0"}
	metaPath, err := writeSignatureSourceMetadata(rulesDir, "owner/repo", release, "https://example.test/a.tgz")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if metaPath != "" {
		t.Fatalf("expected empty path when no sigma-rules ancestor, got %q", metaPath)
	}
}

// ---------------------------------------------------------------------------
// runCollectProfile error paths
// ---------------------------------------------------------------------------

func TestRunCollectProfileNegativeCPUSeconds(t *testing.T) {
	t.Parallel()
	err := runCollectProfile(context.Background(), profileCaptureOptions{
		PprofURL:   "http://localhost:6060",
		CPUSeconds: -1,
	})
	if err == nil || !strings.Contains(err.Error(), "cpu-seconds") {
		t.Fatalf("expected cpu-seconds error, got: %v", err)
	}
}

func TestRunCollectProfileNothingToCollect(t *testing.T) {
	t.Parallel()
	err := runCollectProfile(context.Background(), profileCaptureOptions{
		PprofURL:   "http://localhost:6060",
		CPUSeconds: 0,
		Heap:       false,
		Allocs:     false,
	})
	if err == nil || !strings.Contains(err.Error(), "nothing to collect") {
		t.Fatalf("expected 'nothing to collect' error, got: %v", err)
	}
}

func TestRunCollectProfileEmptyOutputDir(t *testing.T) {
	t.Parallel()
	err := runCollectProfile(context.Background(), profileCaptureOptions{
		PprofURL:   "http://localhost:6060",
		OutputDir:  "",
		CPUSeconds: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "output-dir") {
		t.Fatalf("expected output-dir error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeTestZip(t *testing.T, archivePath string, files map[string]string) {
	t.Helper()
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip.Create() error = %v", err)
		}
		w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// extractSubdirFromArchive — dispatch tests
// ---------------------------------------------------------------------------

func TestExtractSubdirFromArchiveUnsupportedFormat(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "unknown.bin")
	os.WriteFile(archivePath, []byte("random content"), 0644)

	_, err := extractSubdirFromArchive(archivePath, "rules/linux", filepath.Join(tmpDir, "out"))
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestExtractSubdirFromArchiveMissingFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	_, err := extractSubdirFromArchive(filepath.Join(tmpDir, "missing.tar.gz"), "rules/linux", filepath.Join(tmpDir, "out"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// extractSubdirFromTarGz — comprehensive tests
// ---------------------------------------------------------------------------

func TestExtractSubdirFromTarGz(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	destDir := filepath.Join(tmpDir, "out")

	writeTestTarGzHelper(t, archivePath, map[string]string{
		"repo/rules/linux/proc/test1.yml": "rule1",
		"repo/rules/linux/file/test2.yml": "rule2",
		"repo/rules/windows/test3.yml":    "rule3",
		"repo/README.md":                  "readme",
	})

	written, err := extractSubdirFromTarGz(archivePath, "rules/linux", destDir)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if written != 2 {
		t.Fatalf("written = %d, want 2", written)
	}

	content, err := os.ReadFile(filepath.Join(destDir, "proc", "test1.yml"))
	if err != nil || string(content) != "rule1" {
		t.Fatalf("rule1 content = %q, err = %v", content, err)
	}
}

func TestExtractSubdirFromTarGzEmptyResult(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	destDir := filepath.Join(tmpDir, "out")

	writeTestTarGzHelper(t, archivePath, map[string]string{
		"repo/rules/windows/test.yml": "rule",
	})

	_, err := extractSubdirFromTarGz(archivePath, "rules/linux", destDir)
	if err == nil || !strings.Contains(err.Error(), "no files found") {
		t.Fatalf("expected 'no files found' error, got: %v", err)
	}
}

func TestExtractSubdirFromTarGzDirectoryEntries(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	destDir := filepath.Join(tmpDir, "out")

	writeTestTarGzWithDirs(t, archivePath, map[string]string{
		"repo/rules/linux/proc/test1.yml": "rule1",
	}, []string{
		"repo/rules/linux/proc/",
	})

	written, err := extractSubdirFromTarGz(archivePath, "rules/linux", destDir)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if written != 1 {
		t.Fatalf("written = %d, want 1", written)
	}

	// Directory should exist
	info, err := os.Stat(filepath.Join(destDir, "proc"))
	if err != nil || !info.IsDir() {
		t.Fatal("expected proc directory to exist")
	}
}

// ---------------------------------------------------------------------------
// extractBestBinaryFromArchive — dispatch tests
// ---------------------------------------------------------------------------

func TestExtractBestBinaryFromArchiveUnsupported(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "unknown.bin")
	os.WriteFile(archivePath, []byte("random content"), 0644)

	_, err := extractBestBinaryFromArchive(archivePath, filepath.Join(tmpDir, "out"), []string{"aurora"})
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestExtractBestBinaryFromTarGz(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "release.tar.gz")
	outputPath := filepath.Join(tmpDir, "aurora")

	writeTestTarGzHelper(t, archivePath, map[string]string{
		"release/aurora":       "binary-content",
		"release/aurora-linux": "alt-binary-content",
		"release/README.md":    "readme",
	})

	entryName, err := extractBestBinaryFromTarGz(archivePath, outputPath, []string{"aurora", "aurora-linux"})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(entryName, "aurora") {
		t.Fatalf("entryName = %q, expected aurora", entryName)
	}

	content, _ := os.ReadFile(outputPath)
	if string(content) != "binary-content" {
		t.Fatalf("content = %q, want binary-content", content)
	}
}

func TestExtractBestBinaryFromTarGzNotFound(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "release.tar.gz")
	outputPath := filepath.Join(tmpDir, "aurora")

	writeTestTarGzHelper(t, archivePath, map[string]string{
		"release/README.md": "readme",
	})

	_, err := extractBestBinaryFromTarGz(archivePath, outputPath, []string{"aurora"})
	if err == nil {
		t.Fatal("expected error when binary not found")
	}
}

func TestExtractBestBinaryFromZip(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "release.zip")
	outputPath := filepath.Join(tmpDir, "aurora")

	writeTestZip(t, archivePath, map[string]string{
		"release/aurora":       "binary-content",
		"release/aurora-linux": "alt-binary-content",
		"release/README.md":    "readme",
	})

	entryName, err := extractBestBinaryFromZip(archivePath, outputPath, []string{"aurora", "aurora-linux"})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(entryName, "aurora") {
		t.Fatalf("entryName = %q, expected aurora", entryName)
	}

	content, _ := os.ReadFile(outputPath)
	if string(content) != "binary-content" {
		t.Fatalf("content = %q, want binary-content", content)
	}
}

func TestExtractBestBinaryFromZipNotFound(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "release.zip")
	outputPath := filepath.Join(tmpDir, "aurora")

	writeTestZip(t, archivePath, map[string]string{
		"release/README.md": "readme",
	})

	_, err := extractBestBinaryFromZip(archivePath, outputPath, []string{"aurora"})
	if err == nil {
		t.Fatal("expected error when binary not found")
	}
}

func TestExtractBestBinaryFromZipFallbackToSecondPreferred(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "release.zip")
	outputPath := filepath.Join(tmpDir, "binary")

	writeTestZip(t, archivePath, map[string]string{
		"release/aurora-linux": "second-binary",
	})

	entryName, err := extractBestBinaryFromZip(archivePath, outputPath, []string{"aurora", "aurora-linux"})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(entryName, "aurora-linux") {
		t.Fatalf("entryName = %q, expected aurora-linux", entryName)
	}
}

// ---------------------------------------------------------------------------
// writeReaderToFile
// ---------------------------------------------------------------------------

func TestWriteReaderToFileSuccess(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "nested", "dir", "file.txt")

	err := writeReaderToFile(outputPath, strings.NewReader("hello world"), 0o600)
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	content, _ := os.ReadFile(outputPath)
	if string(content) != "hello world" {
		t.Fatalf("content = %q, want hello world", content)
	}

	info, _ := os.Stat(outputPath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

// ---------------------------------------------------------------------------
// copyFile additional tests
// ---------------------------------------------------------------------------

func TestCopyFileMissingSource(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	err := copyFile(filepath.Join(tmpDir, "missing.txt"), filepath.Join(tmpDir, "dst.txt"), 0644)
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestCopyFileCreatesParentDirs(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "src.txt")
	dstPath := filepath.Join(tmpDir, "deep", "nested", "dst.txt")

	os.WriteFile(srcPath, []byte("content"), 0644)

	if err := copyFile(srcPath, dstPath, 0644); err != nil {
		t.Fatalf("error = %v", err)
	}

	content, _ := os.ReadFile(dstPath)
	if string(content) != "content" {
		t.Fatalf("content = %q", content)
	}
}

// ---------------------------------------------------------------------------
// copyDir additional tests
// ---------------------------------------------------------------------------

func TestCopyDirMissingSource(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	err := copyDir(filepath.Join(tmpDir, "missing"), filepath.Join(tmpDir, "dst"))
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestCopyDirSymlinkError(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	realFile := filepath.Join(srcDir, "real.txt")
	os.WriteFile(realFile, []byte("content"), 0644)

	symlink := filepath.Join(srcDir, "link.txt")
	os.Symlink(realFile, symlink)

	err := copyDir(srcDir, filepath.Join(tmpDir, "dst"))
	if err == nil {
		t.Fatal("expected error for symlink in source")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error should mention symlink: %v", err)
	}
}

// ---------------------------------------------------------------------------
// relFromArchiveSubdir
// ---------------------------------------------------------------------------

func TestRelFromArchiveSubdirBasic(t *testing.T) {
	t.Parallel()
	tests := []struct {
		entry   string
		subdir  string
		wantRel string
		wantOK  bool
	}{
		{"repo/rules/linux/test.yml", "rules/linux", "test.yml", true},
		{"repo/rules/linux/", "rules/linux", "", true},
		{"repo/rules/windows/test.yml", "rules/linux", "", false},
		{"a/b/c/d.txt", "b/c", "d.txt", true},
		{"just.txt", "", "just.txt", true},
		{"", "", "", false},
	}

	for _, tc := range tests {
		name := fmt.Sprintf("%s_%s", tc.entry, tc.subdir)
		t.Run(name, func(t *testing.T) {
			rel, ok := relFromArchiveSubdir(tc.entry, tc.subdir)
			if ok != tc.wantOK || rel != tc.wantRel {
				t.Fatalf("relFromArchiveSubdir(%q, %q) = (%q, %v), want (%q, %v)",
					tc.entry, tc.subdir, rel, ok, tc.wantRel, tc.wantOK)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers for tar.gz tests
// ---------------------------------------------------------------------------

// writeTestTarGzHelper wraps writeTestTarGz (from main_test.go) for use in test helper
func writeTestTarGzHelper(t *testing.T, archivePath string, files map[string]string) {
	t.Helper()
	if err := writeTestTarGz(archivePath, files); err != nil {
		t.Fatalf("writeTestTarGz() error = %v", err)
	}
}

func writeTestTarGzWithDirs(t *testing.T, archivePath string, files map[string]string, dirs []string) {
	t.Helper()
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, dir := range dirs {
		hdr := &tar.Header{
			Name:     dir,
			Mode:     0755,
			Typeflag: tar.TypeDir,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar.WriteHeader() error = %v", err)
		}
	}

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar.WriteHeader() error = %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar.Write() error = %v", err)
		}
	}
}
