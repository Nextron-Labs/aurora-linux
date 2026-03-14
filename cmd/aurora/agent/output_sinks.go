package agent

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/logging"
	log "github.com/sirupsen/logrus"
)

type formattedOutputHook struct {
	formatter log.Formatter
	writer    io.Writer
}

func (h *formattedOutputHook) Levels() []log.Level {
	return log.AllLevels
}

func (h *formattedOutputHook) Fire(entry *log.Entry) error {
	if h == nil || h.formatter == nil || h.writer == nil {
		return nil
	}

	line, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}
	_, err = h.writer.Write(line)
	return err
}

func formatterForOutputFormat(format string) log.Formatter {
	switch format {
	case outputFormatJSON:
		return &logging.JSONFormatter{}
	default:
		return &logging.SyslogFormatter{AppName: "aurora"}
	}
}

type networkWriter struct {
	mu      sync.Mutex
	network string
	target  string
	dialer  net.Dialer
	conn    net.Conn
}

func newNetworkWriter(network string, target string) (*networkWriter, error) {
	switch network {
	case "tcp", "udp":
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}

	return &networkWriter{
		network: network,
		target:  target,
		dialer: net.Dialer{
			Timeout: 3 * time.Second,
		},
	}, nil
}

func (w *networkWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureConnLocked(); err != nil {
		return 0, err
	}

	n, err := writeAllWithDeadline(w.conn, p)
	if err == nil {
		return n, nil
	}

	// Retry once with a fresh connection.
	_ = w.closeConnLocked()
	if err := w.ensureConnLocked(); err != nil {
		return n, err
	}
	return writeAllWithDeadline(w.conn, p)
}

func (w *networkWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeConnLocked()
}

func (w *networkWriter) ensureConnLocked() error {
	if w.conn != nil {
		return nil
	}

	conn, err := w.dialer.Dial(w.network, w.target)
	if err != nil {
		return fmt.Errorf("dialing %s target %q: %w", w.network, w.target, err)
	}
	w.conn = conn
	return nil
}

func (w *networkWriter) closeConnLocked() error {
	if w.conn == nil {
		return nil
	}
	err := w.conn.Close()
	w.conn = nil
	return err
}

func writeAllWithDeadline(conn net.Conn, payload []byte) (int, error) {
	total := 0
	for total < len(payload) {
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Write(payload[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
