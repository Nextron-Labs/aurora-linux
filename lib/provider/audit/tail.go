package audit

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

// lineReader splits a growing file into lines. Unlike bufio.Reader.ReadLine it
// never reports a line until its newline has arrived, so a line caught mid-write
// at EOF is held back instead of being returned in two pieces.
type lineReader struct {
	r   *bufio.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReader(r)}
}

// next returns the next complete line without its line ending. Bytes beyond
// maxAuditLineBytes are discarded to prevent unbounded allocation. On error,
// including io.EOF, any partial line is kept for a later call or for remainder.
func (l *lineReader) next() (string, error) {
	for {
		chunk, err := l.r.ReadSlice('\n')
		if room := maxAuditLineBytes - len(l.buf); room > 0 {
			l.buf = append(l.buf, chunk[:min(room, len(chunk))]...)
		}
		switch {
		case err == nil:
			return l.remainder(), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return "", err
		}
	}
}

// remainder returns the buffered line, complete or not, and clears it. Use it
// once no more data will arrive, to pick up a final line with no newline.
func (l *lineReader) remainder() string {
	line := strings.TrimRight(string(l.buf), "\r\n")
	l.buf = l.buf[:0]
	return line
}

// reset discards all buffered data and continues reading from r.
func (l *lineReader) reset(r io.Reader) {
	l.r.Reset(r)
	l.buf = l.buf[:0]
}

// logStatus says how the file at a log's path relates to the open descriptor.
type logStatus int

const (
	logUnchanged logStatus = iota
	logRotated             // the path now refers to a different file
	logTruncated           // the open file is shorter than the read position
)

// auditLog is an open audit log file being read line by line.
type auditLog struct {
	path   string
	file   *os.File
	lines  *lineReader
	lineNo int
}

func openAuditLog(path string) (*auditLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &auditLog{path: path, file: f, lines: newLineReader(f)}, nil
}

func (l *auditLog) close() {
	_ = l.file.Close()
}

func (l *auditLog) seekToEnd() error {
	_, err := l.file.Seek(0, io.SeekEnd)
	return err
}

// rewind restarts reading from the beginning of the file.
func (l *auditLog) rewind() error {
	if _, err := l.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	l.lines.reset(l.file)
	l.lineNo = 0
	return nil
}

// status checks for rotation and truncation. Call it only after reading to EOF,
// when the descriptor's position matches what has been consumed.
func (l *auditLog) status() logStatus {
	onDisk, err := os.Stat(l.path)
	if err != nil {
		// Renamed away with no replacement yet. Keep the open descriptor until
		// a new file appears.
		return logUnchanged
	}
	opened, err := l.file.Stat()
	if err != nil {
		return logUnchanged
	}
	if !os.SameFile(opened, onDisk) {
		return logRotated
	}
	if pos, err := l.file.Seek(0, io.SeekCurrent); err == nil && opened.Size() < pos {
		return logTruncated
	}
	return logUnchanged
}
