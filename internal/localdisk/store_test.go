package localdisk

import (
	"strings"
	"testing"
	"time"
)

func TestOpenReturnsHelpfulLockMessage(t *testing.T) {
	path := t.TempDir() + "/local.db"

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open(first) error = %v", err)
	}
	defer first.Close()

	second, err := openWithTimeout(path, 50*time.Millisecond)
	if err == nil {
		_ = second.Close()
		t.Fatal("Open(second) error = nil, want lock timeout")
	}
	if !strings.Contains(err.Error(), "multiple pods/processes") {
		t.Fatalf("Open(second) error = %v, want helpful lock hint", err)
	}
}
