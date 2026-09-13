package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type FileMutex struct {
	file   *os.File
	locker sync.Mutex
}

func (fm *FileMutex) Write(data string) error {
	fm.locker.Lock()
	defer fm.locker.Unlock()

	_, err := fm.file.WriteString(data)
	return err
}

func (fm *FileMutex) Close() error {
	fm.locker.Lock()
	defer fm.locker.Unlock()

	return fm.file.Close()
}

func resultFile(csv bool) *os.File {
	if csv {
		will_be_created := false
		_, exist := os.Stat("result.csv")
		if exist != nil {
			will_be_created = true
		}
		csv_file, err := os.OpenFile("result.csv", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			exitOnError(fmt.Errorf("failed to open result.csv: %w", err))
		}
		if will_be_created {
			csv_file.Write([]byte("ip:port,ping,latency,jitter,download,upload\n"))
		}
		return csv_file
	} else {
		file, err := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			exitOnError(fmt.Errorf("failed to open result.txt: %w", err))
		}
		return file
	}
}

// resolveFilePath resolves a file path by checking the current working directory first,
// and if not found and the path is relative, checking beside the running executable.
func resolveFilePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return p
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if !filepath.IsAbs(p) {
		if exePath, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(exePath), p)
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	return p
}
