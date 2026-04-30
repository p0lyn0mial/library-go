package fsutil

import (
	"os"
	"path/filepath"
)

// WriteFileFsync writes data to the named file and fsyncs both the file and
// its parent directory to ensure the content and the directory entry are
// durable on disk. This is necessary because os.WriteFile only writes to
// the kernel page cache. Without fsync, an ungraceful shutdown can result
// in truncated or missing files even though the write appeared to succeed.
func WriteFileFsync(name string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(name, data, perm); err != nil {
		return err
	}
	if err := fsync(name); err != nil {
		return err
	}
	return fsync(filepath.Dir(name))
}

func fsync(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
