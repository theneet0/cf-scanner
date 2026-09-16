package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestWaitOnWindows_NonBlockingOnEOF(t *testing.T) {
	// Create an empty pipe to simulate closed/EOF stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	// Close write end so read will immediately return EOF
	_ = w.Close()

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	os.Stdin = r

	done := make(chan struct{})
	go func() {
		waitOnWindows()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded immediately on EOF without hanging
	case <-time.After(2 * time.Second):
		t.Fatal("waitOnWindows hung indefinitely on EOF")
	}
}

func TestWaitOnWindows_ReadsNewline(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	os.Stdin = r

	// Write newline to pipe to simulate user pressing Enter
	go func() {
		_, _ = w.Write([]byte("\n"))
		_ = w.Close()
	}()

	done := make(chan struct{})
	go func() {
		waitOnWindows()
		close(done)
	}()

	select {
	case <-done:
		// Successfully unblocked after user pressed Enter
	case <-time.After(2 * time.Second):
		t.Fatal("waitOnWindows did not unblock after newline was sent")
	}
}

func TestExitOnError_NilIsNoop(t *testing.T) {
	// Should do nothing when err is nil
	exitOnError(nil)
}

func TestExitOnError_InvokesExitFunc(t *testing.T) {
	// Create an empty pipe for stdin so waitOnWindows won't block on Windows
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	_ = w.Close()
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	os.Stdin = r

	var exitedCode int
	var exitCalled bool
	oldExit := exitFunc
	defer func() {
		exitFunc = oldExit
		resetExitOnceForTest()
	}()

	exitFunc = func(code int) {
		exitCalled = true
		exitedCode = code
	}
	resetExitOnceForTest()

	exitOnError("simulated fatal error")

	if !exitCalled {
		t.Fatal("exitOnError did not call exitFunc")
	}
	if exitedCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitedCode)
	}
}

func TestDefaultConf(t *testing.T) {
	conf := defaultConf()
	if conf.Hostname != "cp.cloudflare.com" {
		t.Errorf("expected hostname cp.cloudflare.com, got %s", conf.Hostname)
	}
	if len(conf.Ports) != 1 || conf.Ports[0] != 443 {
		t.Errorf("expected default port [443], got %v", conf.Ports)
	}
	if !conf.TLS.Enable {
		t.Errorf("expected TLS to be enabled in default conf")
	}
	if !conf.Ping.Privileged {
		t.Errorf("expected privileged ping in default conf matching conf.json")
	}
	if !conf.ProgressBar {
		t.Errorf("expected ProgressBar to be enabled by default")
	}
	if !conf.Log {
		t.Errorf("expected Log to be enabled by default")
	}
}

func TestConfJSONUnmarshal(t *testing.T) {
	data, err := os.ReadFile("conf.json")
	if err != nil {
		t.Fatalf("failed to read conf.json: %v", err)
	}

	var conf Conf
	if err := json.Unmarshal(data, &conf); err != nil {
		t.Fatalf("failed to unmarshal conf.json: %v", err)
	}

	if !conf.ProgressBar {
		t.Errorf("expected conf.json ProgressBar to be true")
	}
	if !conf.Log {
		t.Errorf("expected conf.json Log to be true")
	}
	if conf.Hostname != "cp.cloudflare.com" {
		t.Errorf("expected conf.json Hostname to be cp.cloudflare.com, got %s", conf.Hostname)
	}
	if conf.UploadTest.Url != "https://speed.cloudflare.com/__up" {
		t.Errorf("expected conf.json UploadTest.Url to be preserved, got %s", conf.UploadTest.Url)
	}
	if conf.DownloadTest.Url != "https://speed.cloudflare.com/__down?bytes=10000000" {
		t.Errorf("expected conf.json DownloadTest.Url to be preserved, got %s", conf.DownloadTest.Url)
	}
}

