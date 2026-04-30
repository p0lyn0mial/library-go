package fsutil

import (
	"os"
	"path/filepath"
)

// WriteFileFsync writes data to a file and fsyncs both the file and its
// parent directory to ensure the write is durable on disk.
func WriteFileFsync(name string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(name, data, perm); err != nil {
		return err
	}
	if err := Fsync(name); err != nil {
		return err
	}
	return Fsync(filepath.Dir(name))
}

// Fsync fsyncs a file or directory to ensure it is durable on disk.
func Fsync(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
