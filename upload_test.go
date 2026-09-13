package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestZeroStreamReader verifies zeroStreamReader bounds, zero-filling, EOF, and atomic counting.
func TestZeroStreamReader(t *testing.T) {
	t.Run("EmptyBuffer", func(t *testing.T) {
		var uploaded int64
		r := &zeroStreamReader{
			remaining: 100,
			uploaded:  &uploaded,
		}
		buf := make([]byte, 0)
		n, err := r.Read(buf)
		if n != 0 || err != nil {
			t.Fatalf("expected (0, nil), got (%d, %v)", n, err)
		}
		if atomic.LoadInt64(&uploaded) != 0 {
			t.Fatalf("expected uploaded 0, got %d", uploaded)
		}
	})

	t.Run("ZeroTargetBytes", func(t *testing.T) {
		var uploaded int64
		r := &zeroStreamReader{
			remaining: 0,
			uploaded:  &uploaded,
		}
		buf := make([]byte, 1024)
		n, err := r.Read(buf)
		if n != 0 || err != io.EOF {
			t.Fatalf("expected (0, io.EOF), got (%d, %v)", n, err)
		}
		if atomic.LoadInt64(&uploaded) != 0 {
			t.Fatalf("expected uploaded 0, got %d", uploaded)
		}
	})

	t.Run("SmallerThanBuffer", func(t *testing.T) {
		var uploaded int64
		const target = 500
		r := &zeroStreamReader{
			remaining: target,
			uploaded:  &uploaded,
		}
		buf := make([]byte, 1024)
		for i := range buf {
			buf[i] = 0xFF // dirty buffer
		}
		n, err := r.Read(buf)
		if n != target || err != nil {
			t.Fatalf("expected (%d, nil), got (%d, %v)", target, n, err)
		}
		for i := 0; i < n; i++ {
			if buf[i] != 0 {
				t.Fatalf("expected 0 byte at index %d, got %d", i, buf[i])
			}
		}
		// next read should return EOF
		n2, err2 := r.Read(buf)
		if n2 != 0 || err2 != io.EOF {
			t.Fatalf("expected (0, io.EOF), got (%d, %v)", n2, err2)
		}
		if atomic.LoadInt64(&uploaded) != target {
			t.Fatalf("expected uploaded %d, got %d", target, uploaded)
		}
	})

	t.Run("MultiChunkStream", func(t *testing.T) {
		var uploaded int64
		const target = 100000
		r := &zeroStreamReader{
			remaining: target,
			uploaded:  &uploaded,
		}
		buf := make([]byte, 8192)
		var totalRead int64
		for {
			for i := range buf {
				buf[i] = 0xAA
			}
			n, err := r.Read(buf)
			totalRead += int64(n)
			for i := 0; i < n; i++ {
				if buf[i] != 0 {
					t.Fatalf("non-zero byte at index %d", i)
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if totalRead != target {
			t.Fatalf("expected totalRead %d, got %d", target, totalRead)
		}
		if atomic.LoadInt64(&uploaded) != target {
			t.Fatalf("expected uploaded %d, got %d", target, uploaded)
		}
	})

	t.Run("ConcurrentReadThreadSafety", func(t *testing.T) {
		var uploaded int64
		const target = 500000
		r := &zeroStreamReader{
			remaining: target,
			uploaded:  &uploaded,
		}
		var wg sync.WaitGroup
		var totalConcurrentRead int64
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, 1024)
				for {
					n, err := r.Read(buf)
					if n > 0 {
						atomic.AddInt64(&totalConcurrentRead, int64(n))
					}
					if err == io.EOF {
						break
					}
				}
			}()
		}
		wg.Wait()
		if totalConcurrentRead != target {
			t.Fatalf("expected concurrent read %d, got %d", target, totalConcurrentRead)
		}
		if atomic.LoadInt64(&uploaded) != target {
			t.Fatalf("expected uploaded %d, got %d", target, uploaded)
		}
	})
}

// TestUploadTestScenarios tests uploadTest with various HTTP server responses and edge cases.
func TestUploadTestScenarios(t *testing.T) {
	t.Run("Success200OK", func(t *testing.T) {
		var receivedBytes int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			atomic.StoreInt64(&receivedBytes, n)
			if n != 100000 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		ip := net.ParseIP(host)
		addr := net.TCPAddr{IP: ip, Port: port}

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                server.URL,
				SNI:                "localhost",
				TargetBytes:        100000,
				Timeout:            3000,
			},
		}

		res := uploadTest(server.Client(), &conf, addr, utls.HelloChrome_Auto, nil)
		if !bytes.Contains([]byte(res), []byte("MB/S")) {
			t.Fatalf("expected MB/S result, got: %s", res)
		}
		if atomic.LoadInt64(&receivedBytes) != 100000 {
			t.Fatalf("expected server to receive exactly 100000 bytes, got %d", receivedBytes)
		}
	})

	t.Run("Success204NoContent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		ip := net.ParseIP(host)
		addr := net.TCPAddr{IP: ip, Port: port}

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                server.URL,
				SNI:                "localhost",
				TargetBytes:        50000,
				Timeout:            3000,
			},
		}

		res := uploadTest(server.Client(), &conf, addr, utls.HelloChrome_Auto, nil)
		if !bytes.Contains([]byte(res), []byte("MB/S")) {
			t.Fatalf("expected MB/S result, got: %s", res)
		}
	})

	t.Run("FailedStatusCode500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		ip := net.ParseIP(host)
		addr := net.TCPAddr{IP: ip, Port: port}

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                server.URL,
				SNI:                "localhost",
				TargetBytes:        50000,
				Timeout:            3000,
			},
		}

		res := uploadTest(server.Client(), &conf, addr, utls.HelloChrome_Auto, nil)
		if res != "FAILED" {
			t.Fatalf("expected FAILED, got: %s", res)
		}
	})

	t.Run("TimeoutExceeded", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(500 * time.Millisecond):
				w.WriteHeader(http.StatusOK)
			case <-r.Context().Done():
				return
			}
		}))
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		ip := net.ParseIP(host)
		addr := net.TCPAddr{IP: ip, Port: port}

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                server.URL,
				SNI:                "localhost",
				TargetBytes:        10000,
				Timeout:            100, // 100ms timeout vs 500ms delay
			},
		}

		res := uploadTest(server.Client(), &conf, addr, utls.HelloChrome_Auto, nil)
		if res != "Timeout" {
			t.Fatalf("expected Timeout, got: %s", res)
		}
	})

	t.Run("JammedPrematureClose", func(t *testing.T) {
		// Create raw TCP listener to simulate connection abort midway through upload
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer l.Close()

		tcpAddr := l.Addr().(*net.TCPAddr)

		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Read through headers until body begins, then read some body bytes
			buf := make([]byte, 8192)
			totalRead := 0
			for {
				n, err := conn.Read(buf[totalRead:])
				if err != nil {
					return
				}
				totalRead += n
				// Check if headers ended (\r\n\r\n) and at least 100 body bytes arrived
				if idx := bytes.Index(buf[:totalRead], []byte("\r\n\r\n")); idx != -1 {
					bodyBytes := totalRead - (idx + 4)
					if bodyBytes >= 100 {
						break
					}
				}
				if totalRead == len(buf) {
					break
				}
			}
			// Close abruptly with TCP RST while uploaded > 0
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
		}()

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                fmt.Sprintf("http://127.0.0.1:%d/upload", tcpAddr.Port),
				SNI:                "localhost",
				TargetBytes:        1000000,
				Timeout:            3000,
			},
		}

		client := &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		}

		res := uploadTest(client, &conf, *tcpAddr, utls.HelloChrome_Auto, nil)
		// Strict assertion: must be JAMMED because body bytes were transferred before connection abort
		if res != "JAMMED" {
			t.Fatalf("expected JAMMED, got: %s", res)
		}
	})

	t.Run("JammedServerReturnsEarly200", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer l.Close()

		tcpAddr := l.Addr().(*net.TCPAddr)

		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Read headers and only small portion of body
			buf := make([]byte, 4096)
			totalRead := 0
			for {
				n, err := conn.Read(buf[totalRead:])
				if err != nil {
					return
				}
				totalRead += n
				if idx := bytes.Index(buf[:totalRead], []byte("\r\n\r\n")); idx != -1 {
					bodyBytes := totalRead - (idx + 4)
					if bodyBytes >= 100 {
						break
					}
				}
				if totalRead == len(buf) {
					break
				}
			}

			// Send 200 OK and close connection before full 10MB transfer completes
			resp := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			_, _ = conn.Write([]byte(resp))
		}()

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                fmt.Sprintf("http://127.0.0.1:%d/upload", tcpAddr.Port),
				SNI:                "localhost",
				TargetBytes:        10000000, // 10MB target
				Timeout:            3000,
			},
		}

		client := &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		}

		res := uploadTest(client, &conf, *tcpAddr, utls.HelloChrome_Auto, nil)
		if res != "JAMMED" {
			t.Fatalf("expected JAMMED, got: %s", res)
		}
	})

	t.Run("NetworkErrorBeforeTransfer", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		tcpAddr := l.Addr().(*net.TCPAddr)
		_ = l.Close() // Close immediately so dial fails before transfer begins

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                fmt.Sprintf("http://127.0.0.1:%d/upload", tcpAddr.Port),
				SNI:                "localhost",
				TargetBytes:        100000,
				Timeout:            3000,
			},
		}

		client := &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		}

		res := uploadTest(client, &conf, *tcpAddr, utls.HelloChrome_Auto, nil)
		if res != "FAILED" {
			t.Fatalf("expected FAILED, got: %s", res)
		}
	})

	t.Run("EmptyPathUrl", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		ip := net.ParseIP(host)
		addr := net.TCPAddr{IP: ip, Port: port}

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                server.URL, // e.g. http://127.0.0.1:54321 with no path
				SNI:                "localhost",
				TargetBytes:        20000,
				Timeout:            3000,
			},
		}

		res := uploadTest(server.Client(), &conf, addr, utls.HelloChrome_Auto, nil)
		if !bytes.Contains([]byte(res), []byte("MB/S")) {
			t.Fatalf("expected MB/S, got: %s", res)
		}
	})

	t.Run("DefaultTimeoutFallback", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		ip := net.ParseIP(host)
		addr := net.TCPAddr{IP: ip, Port: port}

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: false,
				Url:                server.URL,
				SNI:                "localhost",
				TargetBytes:        20000,
				Timeout:            0, // 0 timeout should fall back to default (5000ms) rather than instant failure
			},
		}

		res := uploadTest(server.Client(), &conf, addr, utls.HelloChrome_Auto, nil)
		if !bytes.Contains([]byte(res), []byte("MB/S")) {
			t.Fatalf("expected MB/S, got: %s", res)
		}
	})

	t.Run("SeparateConnectionPlainHTTP", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		ip := net.ParseIP(host)
		addr := net.TCPAddr{IP: ip, Port: port}

		conf := Conf{
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: true, // Separate connection branch
				Url:                server.URL,
				SNI:                "localhost",
				TargetBytes:        20000,
				Timeout:            3000,
			},
		}

		res := uploadTest(nil, &conf, addr, utls.HelloChrome_Auto, nil)
		if !bytes.Contains([]byte(res), []byte("MB/S")) {
			t.Fatalf("expected MB/S result, got: %s", res)
		}
	})

	t.Run("SeparateConnectionStandardTLS", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		ip := net.ParseIP(host)
		addr := net.TCPAddr{IP: ip, Port: port}

		sni := "example.com"
		conf := Conf{
			TLS: TLSConfig{
				Enable:   true,
				Insecure: true,
				SNI:      sni,
			},
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: true,
				Url:                server.URL,
				SNI:                sni,
				TargetBytes:        30000,
				Timeout:            3000,
			},
		}

		res := uploadTest(nil, &conf, addr, utls.HelloChrome_Auto, nil)
		if !bytes.Contains([]byte(res), []byte("MB/S")) {
			t.Fatalf("expected MB/S result, got: %s", res)
		}
	})

	t.Run("LiveCloudflareUpload", func(t *testing.T) {
		ip := net.ParseIP("104.16.132.229")
		addr := net.TCPAddr{IP: ip, Port: 443}
		sni := "speed.cloudflare.com"

		conf := Conf{
			TLS: TLSConfig{
				Enable:   true,
				Insecure: false,
				SNI:      sni,
			},
			UploadTest: UploadConfig{
				Enable:             true,
				SeparateConnection: true,
				Url:                "https://speed.cloudflare.com/__up",
				SNI:                sni,
				TargetBytes:        50000,
				Timeout:            5000,
			},
		}

		res := uploadTest(nil, &conf, addr, utls.HelloChrome_Auto, nil)
		if !bytes.Contains([]byte(res), []byte("MB/S")) {
			t.Logf("Live Cloudflare upload result: %s (acceptable if network/firewall blocked)", res)
		} else {
			t.Logf("Live Cloudflare upload verified successfully: %s", res)
		}
	})
}
