package fsutil

import (
	"os"
	"path/filepath"
)

// SyncPath fsyncs a file or directory to ensure it is durable on disk.
func SyncPath(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	return syncAndClose(f)
}

// WriteFileFsync writes data to a file and fsyncs both the file and its
// parent directory to ensure the write is durable on disk.
func WriteFileFsync(name string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := syncAndClose(f); err != nil {
		return err
	}
	return SyncPath(filepath.Dir(name))
}

func syncAndClose(f *os.File) error {
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
