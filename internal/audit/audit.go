// Package audit writes an append-only JSON Lines event log.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	Time   time.Time      `json:"time"`
	Action string         `json:"action"`
	Status string         `json:"status"`
	Detail map[string]any `json:"detail,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// Log appends events to a file. A nil *Log is a no-op.
type Log struct {
	mu   sync.Mutex
	path string
}

// Open prepares the log file's directory.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return &Log{path: path}, nil
}

// Record appends an event.
func (l *Log) Record(action, status string, detail map[string]any, err error) {
	if l == nil {
		return
	}
	ev := Event{Time: time.Now().UTC(), Action: action, Status: status, Detail: detail}
	if err != nil {
		ev.Error = err.Error()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ferr := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if ferr != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(ev)
}
