package runtimestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type File struct {
	path string
}

type Snapshot struct {
	StartedAt     time.Time `json:"started_at"`
	StoppedAt     time.Time `json:"stopped_at,omitempty"`
	Hostname      string    `json:"hostname"`
	PID           int       `json:"pid"`
	InstanceID    string    `json:"instance_id"`
	CleanShutdown bool      `json:"clean_shutdown"`
}

func New(path string) *File {
	return &File{path: filepath.Clean(path)}
}

func (f *File) Path() string {
	if f == nil {
		return ""
	}
	return f.path
}

func (f *File) Load() (Snapshot, error) {
	if f == nil || f.path == "" {
		return Snapshot{}, os.ErrNotExist
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("unmarshal runtime state: %w", err)
	}
	return snapshot, nil
}

func (f *File) Save(snapshot Snapshot) error {
	if f == nil || f.path == "" {
		return errors.New("runtime state path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return fmt.Errorf("mkdir runtime state dir: %w", err)
	}
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal runtime state: %w", err)
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fmt.Errorf("write runtime state tmp: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("rename runtime state: %w", err)
	}
	return nil
}
