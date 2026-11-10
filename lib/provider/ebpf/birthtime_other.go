//go:build !linux

package ebpf

import "time"

func fileBirthTime(string) (time.Time, bool) { return time.Time{}, false }
