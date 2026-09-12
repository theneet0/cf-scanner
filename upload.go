package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// zeroStreamReader generates zero-bytes on the fly up to target bytes without RAM allocation.
type zeroStreamReader struct {
	remaining int64
	uploaded  *int64
}

func (r *zeroStreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	rem := atomic.LoadInt64(&r.remaining)
	for {
		if rem <= 0 {
			return 0, io.EOF
		}
		n := int64(len(p))
		if n > rem {
			n = rem
		}
		if atomic.CompareAndSwapInt64(&r.remaining, rem, rem-n) {
			clear(p[:n])
			atomic.AddInt64(r.uploaded, n)
			return int(n), nil
		}
		rem = atomic.LoadInt64(&r.remaining)
	}
}

func uploadTest(preclient *http.Client, conf *Conf, addr net.TCPAddr, fingerprint utls.ClientHelloID, fragment *Fragment) string {
	configUrl, configUrlErr := url.Parse(conf.UploadTest.Url)
	if configUrlErr != nil {
		log.Fatalln(configUrlErr)
	}

	var client *http.Client
	if !conf.UploadTest.SeparateConnection {
		if preclient != nil {
			c := *preclient
			c.Timeout = 0
			client = &c
		} else {
			client = http.DefaultClient
		}
	} else {
		if configUrl.Scheme == "https" {
			if conf.HTTP3 {
				client = h3transporter(
					conf,
					&conf.UploadTest.SNI,
					&quic.Config{},
				)
			} else {
				if conf.TLS.Utls.Enable {
					uclient, utlsE := utlsTransporter(conf, fingerprint, conf.UploadTest.SNI, addr, fragment)
					if utlsE != nil {
						return "FAILED"
					}
					client = uclient
				} else {
					client = tlsTransporter(conf, &conf.UploadTest.SNI)
				}
			}
		} else {
			client = http.DefaultClient
		}
	}

	var uploadedBytes int64
	stream := &zeroStreamReader{
		remaining: int64(conf.UploadTest.TargetBytes),
		uploaded:  &uploadedBytes,
	}

	timeoutMs := conf.UploadTest.Timeout
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(timeoutMs))
	defer cancel()

	path := configUrl.Path
	if path == "" {
		path = "/"
	}
	req := http.Request{
		Method: "POST",
		URL: &url.URL{
			Scheme:   configUrl.Scheme,
			Host:     addr.String(),
			Path:     path,
			RawQuery: configUrl.RawQuery,
		},
		Host:          configUrl.Host,
		Header:        make(http.Header),
		Body:          io.NopCloser(stream),
		ContentLength: int64(conf.UploadTest.TargetBytes),
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req = *req.WithContext(ctx)

	ch := make(chan string, 1)
	go func() {
		start := time.Now()
		resp, httpErr := client.Do(&req)
		elapsed := time.Since(start).Seconds()
		if httpErr != nil {
			var netErr net.Error
			if errors.Is(httpErr, context.Canceled) || errors.Is(httpErr, context.DeadlineExceeded) || (errors.As(httpErr, &netErr) && netErr.Timeout()) {
				ch <- "Timeout"
				return
			}
			uploaded := atomic.LoadInt64(&uploadedBytes)
			if uploaded > 0 && uploaded < int64(conf.UploadTest.TargetBytes) {
				ch <- "JAMMED"
				return
			}
			if conf.LogErr {
				color.Red("Upload error: %s", httpErr.Error())
			}
			ch <- "FAILED"
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			if conf.LogErr {
				color.Red("Upload host status code: %s", resp.Status)
			}
			ch <- "FAILED"
			return
		}
		uploaded := atomic.LoadInt64(&uploadedBytes)
		if uploaded < int64(conf.UploadTest.TargetBytes) {
			ch <- "JAMMED"
			return
		}
		if elapsed <= 0 {
			elapsed = 0.001
		}
		bytesPerSecond := float64(uploaded) / elapsed
		ch <- fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)
	}()

	select {
	case report := <-ch:
		return report
	case <-time.After(time.Millisecond * time.Duration(timeoutMs)):
		return "Timeout"
	}
}
