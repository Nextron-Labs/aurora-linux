//go:build linux

package ebpf

import (
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func canaryActions(nonce string) {
	var si unix.Sysinfo_t
	_ = unix.Sysinfo(&si)

	name := os.TempDir() + "/.aurora-canary-" + nonce
	// O_EXCL|O_NOFOLLOW: /tmp is world-writable and the (random) name is
	// visible in argv, so never follow a planted symlink as root.
	if f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0o600); err == nil {
		f.Close()
		os.Remove(name)
	}

	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+canaryNetPort, 300*time.Millisecond); err == nil {
		c.Close()
	}
}
