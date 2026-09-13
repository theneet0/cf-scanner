package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	probing "github.com/prometheus-community/pro-bing"
	"golang.org/x/net/http2"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	utls "github.com/refraction-networking/utls"
)

type DS struct {
	Enable         bool   `json:"Enable"`
	DomainAsSNI    bool   `json:"DomainAsSNI"`
	DomainAsHost   bool   `json:"DomainAsHost"`
	SkipIPV6       bool   `json:"SkipIPV6"`
	Shuffle        bool   `json:"Shuffle"`
	DomainListPath string `json:"DomainListPath"`
}

type NoisePacket struct {
	Type    string `json:"Type"`
	Payload string `json:"Payload"`
	Sleep   string `json:"Sleep"`
}

type NoiseConfig struct {
	Enable  bool          `json:"Enable"`
	Packets []NoisePacket `json:"Packets"`
}

type DownloadConfig struct {
	Enable             bool   `json:"Enable"`
	SeparateConnection bool   `json:"SeparateConnection"`
	Url                string `json:"Url"`
	SNI                string `json:"SNI"`
	TargetBytes        int    `json:"TargetBytes"`
	Timeout            int    `json:"Timeout"`
}

type UploadConfig struct {
	Enable             bool   `json:"Enable"`
	SeparateConnection bool   `json:"SeparateConnection"`
	Url                string `json:"Url"`
	SNI                string `json:"SNI"`
	TargetBytes        int    `json:"TargetBytes"`
	Timeout            int    `json:"Timeout"`
}

type FragmentConfig struct {
	Enable   bool   `json:"Enable"`
	Length   string `json:"Length"`
	Delay    string `json:"Delay"`
	MaxSplit string `json:"MaxSplit"`
}

type UtlsConfig struct {
	Enable            bool           `json:"Enable"`
	Fingerprint       string         `json:"Fingerprint"`
	TcpTimeout        int64          `json:"TcpTimeout"`
	TcpConnectAttempt int            `json:"TcpConnectAttempt"`
	Fragment          FragmentConfig `json:"Fragment"`
}

type TLSConfig struct {
	Enable   bool       `json:"Enable"`
	SNI      string     `json:"SNI"`
	Insecure bool       `json:"Insecure"`
	Alpn     []string   `json:"Alpn"`
	Utls     UtlsConfig `json:"Utls"`
}

type JitterConfig struct {
	Enable    bool    `json:"Enable"`
	MaxJitter float64 `json:"MaxJitter"`
	Samples   int     `json:"Samples"`
	Interval  int64   `json:"Interval"`
}

type PingConfig struct {
	Enable     bool    `json:"Enable"`
	MaxPing    float64 `json:"MaxPing"`
	Privileged bool    `json:"Privileged"`
	Size       string  `json:"Size"`
}

type Conf struct {
	LogErr             bool                `json:"LogErr"`
	CSV                bool                `json:"CSV"`
	RandomScan         bool                `json:"RandomScan"`
	Hostname           string              `json:"Hostname"`
	Ports              []int               `json:"Ports"`
	Path               string              `json:"Path"`
	Headers            map[string][]string `json:"Headers"`
	ResponseHeader     map[string]string   `json:"ResponseHeader"`
	ResponseStatusCode []int               `json:"ResponseStatusCode"`
	Padding            bool                `json:"Padding"`
	PaddingSize        string              `json:"PaddingSize"`
	Ping               PingConfig          `json:"Ping"`
	Goroutines         int                 `json:"Goroutines"`
	Maxlatency         int64               `json:"Maxlatency"`
	Jitter             JitterConfig        `json:"Jitter"`
	IpVersion          int                 `json:"IpVersion"`
	IplistPath         string              `json:"IplistPath"`
	IgnoreRange        []string            `json:"IgnoreRange"`
	AllowRange         []string            `json:"AllowRange"`
	TLS                TLSConfig           `json:"TLS"`
	HTTP3              bool                `json:"HTTP/3"`
	Noises             NoiseConfig         `json:"Noises"`
	DomainScan         DS                  `json:"DomainScan"`
	DownloadTest       DownloadConfig      `json:"DownloadTest"`
	UploadTest         UploadConfig        `json:"UploadTest"`
}

var (
	recentErrorsLock sync.Mutex
	recentErrors     []string
)

func recordScanError(msg string) {
	recentErrorsLock.Lock()
	defer recentErrorsLock.Unlock()
	if len(recentErrors) < 15 {
		for _, e := range recentErrors {
			if e == msg {
				return
			}
		}
		recentErrors = append(recentErrors, msg)
	}
}

func defaultConf() Conf {
	return Conf{
		LogErr:             true,
		CSV:                false,
		RandomScan:         false,
		Hostname:           "cp.cloudflare.com",
		Ports:              []int{443},
		Path:               "/",
		Headers: map[string][]string{
			"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0"},
		},
		ResponseHeader: map[string]string{
			"Server": "cloudflare",
		},
		ResponseStatusCode: []int{200, 204},
		Padding:            true,
		PaddingSize:        "100-1000",
		Ping: PingConfig{
			Enable:     true,
			MaxPing:    500,
			Privileged: true,
			Size:       "24-65",
		},
		Goroutines: 4,
		Maxlatency: 2000,
		Jitter: JitterConfig{
			Enable:    true,
			MaxJitter: 50.0,
			Samples:   5,
			Interval:  200,
		},
		IpVersion: 4,
		TLS: TLSConfig{
			Enable:   true,
			SNI:      "cp.cloudflare.com",
			Insecure: false,
			Alpn:     []string{"h2", "http/1.1"},
			Utls: UtlsConfig{
				Enable:            true,
				Fingerprint:       "chrome",
				TcpTimeout:        1000,
				TcpConnectAttempt: 1,
				Fragment: FragmentConfig{
					Enable:   false,
					Length:   "50-100",
					Delay:    "10-15",
					MaxSplit: "",
				},
			},
		},
	}
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			exitOnError(fmt.Errorf("fatal crash/panic: %v", r))
		}
	}()

	// Support command line arguments and flags:
	// cf-scanner [options] [IP | CIDR]
	configPath := "conf.json"
	cliIP := ""

	for i := 1; i < len(os.Args); i++ {
		arg := strings.TrimSpace(os.Args[i])
		if arg == "" {
			continue
		}
		switch {
		case arg == "-h" || arg == "--help" || arg == "-help" || arg == "/?":
			fmt.Println("Usage: cf-scanner [options] [IP|CIDR]")
			fmt.Println("\nArguments:")
			fmt.Println("  [IP|CIDR]               Single IP (e.g. 1.1.1.1, 1.1.1.1/32, 2606:4700::1) or CIDR to scan")
			fmt.Println("  [config.json]           Custom JSON config file path")
			fmt.Println("\nOptions:")
			fmt.Println("  -c, --config <file>     Path to configuration file")
			fmt.Println("  -i, --ip <ip>           Single IP or CIDR to scan")
			fmt.Println("  -h, --help              Show this help message")
			waitOnWindows()
			return
		case arg == "-c" || arg == "--config" || arg == "-config":
			if i+1 < len(os.Args) {
				i++
				configPath = strings.TrimSpace(os.Args[i])
			}
		case strings.HasPrefix(arg, "--config="):
			configPath = strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
		case strings.HasPrefix(arg, "-c="):
			configPath = strings.TrimSpace(strings.TrimPrefix(arg, "-c="))
		case arg == "-i" || arg == "--ip" || arg == "-ip":
			if i+1 < len(os.Args) {
				i++
				cliIP = strings.TrimSpace(os.Args[i])
			}
		case strings.HasPrefix(arg, "--ip="):
			cliIP = strings.TrimSpace(strings.TrimPrefix(arg, "--ip="))
		case strings.HasPrefix(arg, "-i="):
			cliIP = strings.TrimSpace(strings.TrimPrefix(arg, "-i="))
		case strings.HasSuffix(strings.ToLower(arg), ".json"):
			configPath = arg
		default:
			if cliIP == "" {
				cliIP = arg
			}
		}
	}

	// Load config file (checking cwd and executable directory)
	resolvedConfigPath := resolveFilePath(configPath)
	cfile, cfile_err := os.ReadFile(resolvedConfigPath)
	conf := Conf{}
	if cfile_err != nil {
		if cliIP != "" {
			conf = defaultConf()
			color.Yellow("Notice: config file '%s' not found; scanning with built-in Cloudflare defaults.\n", configPath)
		} else {
			exitOnError(fmt.Errorf("failed to read config file '%s': %w", configPath, cfile_err))
			return
		}
	} else {
		conf_err := json.Unmarshal(cfile, &conf)
		if conf_err != nil {
			exitOnError(fmt.Errorf("failed to parse config JSON '%s': %w", configPath, conf_err))
			return
		}
	}

	if cliIP != "" {
		conf.IplistPath = cliIP
		if prefix, port, err := parseIPOrPrefixWithPort(cliIP); err == nil {
			if prefix.Addr().Is6() {
				conf.IpVersion = 6
			} else {
				conf.IpVersion = 4
			}
			if port > 0 {
				conf.Ports = []int{port}
			}
		} else {
			// If cliIP is not an existing file on disk, report exact IP parsing error
			if _, statErr := os.Stat(resolveFilePath(cliIP)); statErr != nil {
				exitOnError(fmt.Errorf("invalid IP address or CIDR '%s': %w", cliIP, err))
				return
			}
		}
	} else if prefix, port, err := parseIPOrPrefixWithPort(conf.IplistPath); err == nil {
		if prefix.Addr().Is6() {
			conf.IpVersion = 6
		} else if prefix.Addr().Is4() && conf.IpVersion == 6 {
			conf.IpVersion = 4
		}
		if len(conf.Ports) == 0 && port > 0 {
			conf.Ports = []int{port}
		}
	}

	ips := make([]string, 0, 256)
	switch conf.IpVersion {
	case 4:
		// Generate IPs from CIDRs
		color.Yellow("Generating IPs\n")
		GenIPs(&ips, conf.IplistPath, conf.IgnoreRange, conf.AllowRange)
	case 6:
		// Load CIDRs into list and generate random IPv6 during scan
		trimmedPath := strings.TrimSpace(conf.IplistPath)
		if trimmedPath == "" {
			exitOnError(errors.New("empty IPv6 list path"))
			return
		}
		if prefix, _, err := parseIPOrPrefixWithPort(trimmedPath); err == nil {
			if prefix.IsSingleIP() {
				ips = []string{prefix.Addr().String()}
			} else {
				ips = []string{prefix.String()}
			}
		} else if strings.ContainsAny(trimmedPath, ",;") {
			parts := strings.FieldsFunc(trimmedPath, func(r rune) bool {
				return r == ',' || r == ';'
			})
			for _, part := range parts {
				part = stripComment(part)
				if part == "" {
					continue
				}
				if prefix, _, err := parseIPOrPrefixWithPort(part); err == nil {
					if prefix.IsSingleIP() {
						ips = append(ips, prefix.Addr().String())
					} else {
						ips = append(ips, prefix.String())
					}
				}
			}
		} else {
			resolvedPath := resolveFilePath(trimmedPath)
			file, ipListFileErr := os.ReadFile(resolvedPath)
			if ipListFileErr != nil {
				exitOnError(fmt.Errorf("failed to read IPv6 list file '%s': %w", trimmedPath, ipListFileErr))
				return
			} else {
				content := strings.TrimPrefix(string(file), "\ufeff")
				for line := range strings.Lines(content) {
					line = stripComment(line)
					if line == "" {
						continue
					}
					if prefix, _, err := parseIPOrPrefixWithPort(line); err == nil && prefix.IsSingleIP() {
						ips = append(ips, prefix.Addr().String())
					} else {
						ips = append(ips, line)
					}
				}
			}
		}
	default:
		exitOnError(fmt.Errorf("invalid IP version: %d (must be 4 or 6)", conf.IpVersion))
		return
	}

	if len(ips) == 0 {
		exitOnError(errors.New("no valid IP addresses found to scan"))
		return
	}

	fingerprint := utls.HelloChrome_Auto
	if conf.TLS.Utls.Enable {
		fingerprint = fgen(conf.TLS.Utls.Fingerprint)
	}

	scheme := "http"
	if conf.TLS.Enable {
		scheme = "https"
		if len(conf.Ports) == 0 {
			conf.Ports = append(conf.Ports, 443)
		}
	} else {
		if len(conf.Ports) == 0 {
			conf.Ports = append(conf.Ports, 80)
		}
	}

	LengthMin, LengthMax := parseRange(conf.TLS.Utls.Fragment.Length)
	IntervalMin, IntervalMax := parseRange(conf.TLS.Utls.Fragment.Delay)
	MaxSplitMin, MaxSplitMax := parseRange(conf.TLS.Utls.Fragment.MaxSplit)
	fragment := Fragment{
		PacketsFrom: 0,
		PacketsTo:   1,
		LengthMin:   uint64(LengthMin),
		LengthMax:   uint64(LengthMax),
		IntervalMin: uint64(IntervalMin),
		IntervalMax: uint64(IntervalMax),
		MaxSplitMin: uint64(MaxSplitMin),
		MaxSplitMax: uint64(MaxSplitMax),
	}

	file := FileMutex{
		file: resultFile(conf.CSV),
	}
	defer file.Close()

	var hasScanErrors atomic.Bool
	var successfulScans atomic.Int64
	singleTarget := len(ips) == 1
	LOG := conf.LogErr || singleTarget
	if !conf.DomainScan.Enable {
		goroutines := conf.Goroutines
		if goroutines < 1 {
			goroutines = 1
		}
		if len(ips) < goroutines {
			goroutines = len(ips)
		}
		ip_ch := make(chan string, goroutines)
		var wg sync.WaitGroup
		for range goroutines {
			wg.Go(func() {
				defer func() {
					if r := recover(); r != nil {
						exitOnError(fmt.Errorf("scan worker panic: %v", r))
					}
				}()

				var client *http.Client
				if conf.TLS.Enable {
					if conf.HTTP3 {
						client = h3transporter(&conf, nil, nil)
					} else if !conf.TLS.Utls.Enable {
						client = tlsTransporter(&conf, nil)
					}
				} else {
					client = http.DefaultClient
				}

				for {
					ip, e := <-ip_ch
					if !e {
						break
					}
					minrtt := time.Millisecond
					if conf.Ping.Enable {
						// ping ip
						pinger := probing.New(ip)
						pinger.SetPrivileged(conf.Ping.Privileged)
						pinger.Size = randomRange(conf.Ping.Size)
						pinger.Timeout = time.Duration(conf.Ping.MaxPing) * time.Millisecond
						pinger.Count = 1
						pinging_err := pinger.Run()
						if pinging_err != nil && runtime.GOOS == "windows" {
							// On Windows, try toggling privileged mode if the configured mode fails
							pingerFallback := probing.New(ip)
							pingerFallback.SetPrivileged(!conf.Ping.Privileged)
							pingerFallback.Size = pinger.Size
							pingerFallback.Timeout = pinger.Timeout
							pingerFallback.Count = 1
							if fallbackErr := pingerFallback.Run(); fallbackErr == nil {
								pinging_err = nil
								pinger = pingerFallback
							}
						}
						if pinging_err != nil {
							recordScanError(fmt.Sprintf("PING %s: %s", ip, pinging_err))
							hasScanErrors.Store(true)
							if LOG {
								color.Red("PING: %s", pinging_err)
							}
							continue
						}

						if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.Ping.MaxPing)*time.Millisecond) {
							recordScanError(fmt.Sprintf("PING %s: packet loss or RTT %s > max %v", ip, pinger.Statistics().MinRtt, conf.Ping.MaxPing))
							hasScanErrors.Store(true)
							if LOG {
								color.Red("PING: %s\t%s", ip, pinger.Statistics().MinRtt)
							}
							continue
						}

						minrtt = pinger.Statistics().AvgRtt
					}

					for _, port := range conf.Ports {
						ip := net.ParseIP(ip)
						if ip == nil {
							continue
						}
						addr := net.TCPAddr{IP: ip, Port: port}

						// generate http req
						var hostname string
						if strings.Contains(conf.Hostname, "{ip}") {
							hostname = addr.String()
						} else {
							hostname = conf.Hostname
						}
						req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: addr.String(), Path: conf.Path}, Host: hostname, Header: maps.Clone(conf.Headers)}
						req.Header.Set("Host", hostname)
						if conf.Padding {
							req.Header.Set("Cookie", RandomString(conf.PaddingSize))
						}

						s := time.Now()
						if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
							uclient, utlsE := utlsTransporter(&conf, fingerprint, conf.TLS.SNI, addr, &fragment)
							if utlsE != nil {
								recordScanError(fmt.Sprintf("%s: %s", addr.String(), utlsE))
								hasScanErrors.Store(true)
								if LOG {
									color.Red("%s", utlsE)
								}
								continue
							}
							client = uclient
						}
						client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
						// send request
						respone, http_err := client.Do(&req)
						e := time.Now()
						latency := e.UnixMilli() - s.UnixMilli()
						if http_err != nil {
							recordScanError(fmt.Sprintf("%s: %s", addr.String(), http_err))
							hasScanErrors.Store(true)
							if LOG {
								color.Red("%s", http_err)
							}
							continue
						}

						if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) {
							matchHeadersE := matchHeaders(respone.Header, conf.ResponseHeader)
							if matchHeadersE != nil {
								recordScanError(fmt.Sprintf("%s: %s", addr.String(), matchHeadersE))
								hasScanErrors.Store(true)
								color.Red("%s", matchHeadersE)
								continue
							}
							// Calc jiiter
							jitter_str := "Null"
							download_test := "Null"
							upload_test := "Null"
							if conf.Jitter.Enable {
								latencies := []float64{}
								jammed := false
								for range conf.Jitter.Samples {
									s := time.Now()
									// send request
									_, http_err := client.Do(&req)
									e := time.Now()
									latency := e.UnixMilli() - s.UnixMilli()
									if http_err != nil {
										jammed = true
										break
									}
									latencies = append(latencies, float64(latency))
									if conf.Jitter.Interval > 0 {
										time.Sleep(time.Millisecond * time.Duration(conf.Jitter.Interval))
									}
								}
								if jammed {
									recordScanError(fmt.Sprintf("%s: connection jammed during jitter test", addr.String()))
									hasScanErrors.Store(true)
									if LOG {
										color.Yellow("%s\t%s\t%d\tJAMMED", addr.String(), minrtt, latency)
									}
									continue
								}
								jitter := Calc_jitter(latencies)
								if jitter > conf.Jitter.MaxJitter {
									recordScanError(fmt.Sprintf("%s: jitter %.2f exceeded max %.2f", addr.String(), jitter, conf.Jitter.MaxJitter))
									hasScanErrors.Store(true)
									color.Yellow("%s\t%s\t%d\t%f", addr.String(), minrtt, latency, jitter)
									continue
								}
								jitter_str = fmt.Sprintf("%f", jitter)
							}
							if conf.DownloadTest.Enable {
								download_test = downloadTest(client, &conf, addr, fingerprint, &fragment)
							}
							if conf.UploadTest.Enable {
								upload_test = uploadTest(client, &conf, addr, fingerprint, &fragment)
							}
							successfulScans.Add(1)
							rep := fmt.Sprintf("%-21s %-12s %d\t%s\t%s\t%s\n", addr.String(), minrtt, latency, jitter_str, download_test, upload_test)
							color.Green("%s", rep)
							if conf.CSV {
								file.Write(fmt.Sprintf("%s,%s,%d,%s,%s,%s\n", addr.String(), minrtt, latency, jitter_str, download_test, upload_test))
							} else {
								file.Write(rep)
							}
						} else {
							recordScanError(fmt.Sprintf("%s: HTTP status %d", addr.String(), respone.StatusCode))
							hasScanErrors.Store(true)
							if LOG {
								color.Red("%s\t%s\tHTTP.StatusCode=%d", addr.String(), minrtt, respone.StatusCode)
							}
						}
					}
				}
			})
		}

		if conf.RandomScan {
			switch conf.IpVersion {
			case 4:
				rand.Shuffle(len(ips), func(i, j int) {
					ips[i], ips[j] = ips[j], ips[i]
				})
				for _, ip := range ips {
					ip_ch <- ip
				}
			case 6:
				if isAllSingleIPs(ips) {
					for _, ip := range ips {
						ipv6, e := randomIPv6FromCIDR(ip)
						if e != nil {
							continue
						}
						ip_ch <- ipv6.String()
					}
				} else {
					for {
						ipv6, e := randomIPv6FromCIDR(strings.TrimSpace(ips[rand.Intn(len(ips))]))
						if e != nil {
							continue
						}
						ip_ch <- ipv6.String()
					}
				}
			}
		} else {
			if conf.IpVersion == 6 && !isAllSingleIPs(ips) {
				exitOnError(errors.New("linear scan method is only available for single IPv6 addresses or IPv4; for IPv6 CIDR subnets, enable RandomScan"))
				return
			}
			for _, ip := range ips {
				if pfx, err := parseIPOrPrefix(ip); err == nil && pfx.IsSingleIP() {
					ip_ch <- pfx.Addr().String()
				} else {
					ip_ch <- ip
				}
			}
		}
		close(ip_ch)

		wg.Wait()

		if runtime.GOOS == "windows" {
			if successfulScans.Load() == 0 {
				if hasScanErrors.Load() {
					color.Red("\nNo IP passed the scan. Encountered scan errors:")
					recentErrorsLock.Lock()
					for _, errStr := range recentErrors {
						color.Red("  - %s", errStr)
					}
					recentErrorsLock.Unlock()
				} else {
					color.Yellow("\nNo IP passed the scan criteria.")
				}
			} else {
				color.Cyan("\nScan finished. Total successful: %d", successfulScans.Load())
			}
			waitOnWindows()
		}
	} else {
		// Domain Scan
		resolvedDomainListPath := resolveFilePath(conf.DomainScan.DomainListPath)
		domainListFile, domainListFileErr := os.ReadFile(resolvedDomainListPath)
		if domainListFileErr != nil {
			exitOnError(fmt.Errorf("failed to read domain list file '%s': %w", conf.DomainScan.DomainListPath, domainListFileErr))
			return
		}

		domains := strings.Split(string(domainListFile), "\n")
		if conf.DomainScan.Shuffle {
			rand.Shuffle(len(domains), func(i, j int) {
				domains[i], domains[j] = domains[j], domains[i]
			})
		}

		var domainScanErrors atomic.Bool
		var domainSuccessfulScans atomic.Int64
		var wg sync.WaitGroup
		chunkSize := len(domains) / conf.Goroutines
		if chunkSize < 1 {
			chunkSize = 1
		}
		for domainsChunk := range slices.Chunk(domains, chunkSize) {
			wg.Go(func() {
				defer func() {
					if r := recover(); r != nil {
						exitOnError(fmt.Errorf("domain worker panic: %v", r))
					}
				}()

				for _, domain := range domainsChunk {
					domain := strings.TrimSpace(domain)
					if domain == "" || strings.HasPrefix(domain, "#") || strings.HasPrefix(domain, "//") {
						continue
					}
					ips, resolve_err := net.LookupIP(domain)
					if resolve_err != nil {
						recordScanError(fmt.Sprintf("DNS %s: %s", domain, resolve_err))
						domainScanErrors.Store(true)
						color.HiYellow("%s", resolve_err)
						continue
					}

					for _, ip := range ips {
						if conf.DomainScan.SkipIPV6 {
							if ip.To4() == nil && ip.To16() != nil {
								continue
							}
						}

						minrtt := time.Millisecond
						if conf.Ping.Enable {
							// ping ip
							pinger := probing.New(ip.String())
							pinger.SetPrivileged(conf.Ping.Privileged)
							pinger.Size = randomRange(conf.Ping.Size)
							pinger.Timeout = time.Duration(conf.Ping.MaxPing) * time.Millisecond

							pinger.Count = 1
							pinging_err := pinger.Run()
							if pinging_err != nil && runtime.GOOS == "windows" {
								// On Windows, try toggling privileged mode if the configured mode fails
								pingerFallback := probing.New(ip.String())
								pingerFallback.SetPrivileged(!conf.Ping.Privileged)
								pingerFallback.Size = pinger.Size
								pingerFallback.Timeout = pinger.Timeout
								pingerFallback.Count = 1
								if fallbackErr := pingerFallback.Run(); fallbackErr == nil {
									pinging_err = nil
									pinger = pingerFallback
								}
							}
							if pinging_err != nil {
								recordScanError(fmt.Sprintf("PING %s(%s): %s", domain, ip, pinging_err))
								domainScanErrors.Store(true)
								if LOG {
									color.Red("PING: %s", pinging_err)
								}
								continue
							}

							if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.Ping.MaxPing)*time.Millisecond) {
								recordScanError(fmt.Sprintf("PING %s(%s): packet loss or RTT %s > max %v", domain, ip, pinger.Statistics().MinRtt, conf.Ping.MaxPing))
								domainScanErrors.Store(true)
								if LOG {
									color.Red("PING: %s(%s)\t%s", domain, ip, pinger.Statistics().MinRtt)
								}
								continue
							}

							minrtt = pinger.Statistics().AvgRtt
						}
						for _, port := range conf.Ports {
							addr := net.TCPAddr{IP: ip, Port: port}

							// generate http req
							host := conf.Hostname
							if conf.DomainScan.DomainAsHost {
								host = domain
							}
							req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: addr.String(), Path: conf.Path}, Host: host, Header: maps.Clone(conf.Headers)}
							req.Header.Set("Host", host)
							if conf.Padding {
								req.Header.Set("Cookie", RandomString(conf.PaddingSize))
							}

							sni := conf.TLS.SNI
							if conf.DomainScan.DomainAsSNI {
								sni = domain
							}
							var client *http.Client
							if conf.TLS.Enable {
								if conf.HTTP3 {
									client = h3transporter(&conf, &sni, nil)
								} else if !conf.TLS.Utls.Enable {
									client = tlsTransporter(&conf, &sni)
								}
							} else {
								client = http.DefaultClient
							}

							s := time.Now()
							if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
								uclient, utlsE := utlsTransporter(&conf, fingerprint, sni, addr, &fragment)
								if utlsE != nil {
									recordScanError(fmt.Sprintf("%s(%s): %s", domain, addr.String(), utlsE))
									domainScanErrors.Store(true)
									if LOG {
										color.Red("%s", utlsE)
									}
									continue
								}
								client = uclient
							}
							client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
							// send request
							respone, http_err := client.Do(&req)
							e := time.Now()
							latency := e.UnixMilli() - s.UnixMilli()
							if http_err != nil {
								recordScanError(fmt.Sprintf("%s(%s): %s", domain, addr.String(), http_err))
								domainScanErrors.Store(true)
								if LOG {
									color.Red("%s", http_err)
								}
								continue
							}

							if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) {
								matchHeadersE := matchHeaders(respone.Header, conf.ResponseHeader)
								if matchHeadersE != nil {
									recordScanError(fmt.Sprintf("%s(%s): %s", domain, addr.String(), matchHeadersE))
									domainScanErrors.Store(true)
									color.Red("%s(%s)\t%s", domain, ip, matchHeadersE)
									continue
								}
								// Calc jiiter
								jitter_str := "Null"
								download_test := "Null"
								upload_test := "Null"
								if conf.Jitter.Enable {
									latencies := []float64{}
									jammed := false
									for range conf.Jitter.Samples {
										s := time.Now()
										// send request
										_, http_err := client.Do(&req)
										e := time.Now()
										latency := e.UnixMilli() - s.UnixMilli()
										if http_err != nil {
											jammed = true
											break
										}
										latencies = append(latencies, float64(latency))
										if conf.Jitter.Interval > 0 {
											time.Sleep(time.Millisecond * time.Duration(conf.Jitter.Interval))
										}
									}
									if jammed {
										recordScanError(fmt.Sprintf("%s(%s): connection jammed during jitter test", domain, addr.String()))
										domainScanErrors.Store(true)
										if LOG {
											color.Yellow("%s(%s)\t%s\t%d\tJAMMED", domain, ip, minrtt, latency)
										}
										continue
									}
									jitter := Calc_jitter(latencies)
									if jitter > conf.Jitter.MaxJitter {
										recordScanError(fmt.Sprintf("%s(%s): jitter %.2f exceeded max %.2f", domain, addr.String(), jitter, conf.Jitter.MaxJitter))
										domainScanErrors.Store(true)
										color.Yellow("%s(%s)\t%s\t%d\t%f", domain, ip, minrtt, latency, jitter)
										continue
									}
									jitter_str = fmt.Sprintf("%f", jitter)
								}
								if conf.DownloadTest.Enable {
									download_test = downloadTest(client, &conf, addr, fingerprint, &fragment)
								}
								if conf.UploadTest.Enable {
									upload_test = uploadTest(client, &conf, addr, fingerprint, &fragment)
								}
								domainSuccessfulScans.Add(1)
								rep := fmt.Sprintf("%s:\t%s\t%s\t%d\t%s\t%s\t%s\n", domain, ip, minrtt, latency, jitter_str, download_test, upload_test)
								color.Green("%s", rep)
								if conf.CSV {
									file.Write(fmt.Sprintf("%s:%s,%s,%d,%s,%s,%s\n", domain, ip, minrtt, latency, jitter_str, download_test, upload_test))
								} else {
									file.Write(rep)
								}
							} else {
								recordScanError(fmt.Sprintf("%s(%s): HTTP status %d", domain, addr.String(), respone.StatusCode))
								domainScanErrors.Store(true)
								if LOG {
									color.Red("%s(%s)\t%s\tHTTP.StatusCode=%d", domain, ip, minrtt, respone.StatusCode)
								}
							}
						}
					}
				}
			})
		}

		wg.Wait()

		if runtime.GOOS == "windows" {
			if domainSuccessfulScans.Load() == 0 {
				if domainScanErrors.Load() {
					color.Red("\nNo domain passed the scan. Encountered scan errors:")
					recentErrorsLock.Lock()
					for _, errStr := range recentErrors {
						color.Red("  - %s", errStr)
					}
					recentErrorsLock.Unlock()
				} else {
					color.Yellow("\nNo domain passed the scan criteria.")
				}
			} else {
				color.Cyan("\nDomain scan finished. Total successful: %d", domainSuccessfulScans.Load())
			}
			waitOnWindows()
		}
	}
}

func matchHeaders(headers http.Header, tomatch map[string]string) error {
	for header, value := range tomatch {
		if headers.Get(header) == value {
			continue
		} else {
			return fmt.Errorf("response header not matching")
		}
	}

	return nil
}

func fgen(f string) utls.ClientHelloID {
	var finger utls.ClientHelloID

	switch f {
	case "firefox":
		finger = utls.HelloFirefox_Auto
	case "edge":
		finger = utls.HelloEdge_Auto
	case "chrome":
		finger = utls.HelloChrome_Auto
	case "360":
		finger = utls.Hello360_Auto
	case "ios":
		finger = utls.HelloIOS_Auto
	default:
		exitOnError(fmt.Errorf("invalid fingerprint '%s' (supported: firefox, edge, chrome, 360, ios)", f))
	}

	return finger
}

func RandomString(n string) string {
	bytes := make([]byte, randomRange(n))
	_, err := crand.Read(bytes)
	if err != nil {
		exitOnError(fmt.Errorf("failed to generate random string: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func parseRange(r string) (a int, b int) {
	r = strings.TrimSpace(r)
	if r == "" {
		return 0, 0
	}

	ab := strings.Split(r, "-")
	var a_err, b_err error
	a, a_err = strconv.Atoi(strings.TrimSpace(ab[0]))
	if a_err != nil {
		exitOnError(fmt.Errorf("invalid range '%s': %w", r, a_err))
		return 0, 0
	}
	if len(ab) == 1 {
		return a, a
	}
	b, b_err = strconv.Atoi(strings.TrimSpace(ab[1]))
	if b_err != nil {
		exitOnError(fmt.Errorf("invalid range '%s': %w", r, b_err))
		return 0, 0
	}
	if a > b {
		a, b = b, a
	}
	return a, b
}

func randomRange(r string) int {
	r = strings.TrimSpace(r)
	if r == "" {
		return 0
	}
	a, b := parseRange(r)
	if a == b {
		return a
	}
	return rand.Intn(b-a+1) + a
}

func h3transporter(conf *Conf, sni *string, qc *quic.Config) *http.Client {
	if sni == nil {
		sni = &conf.TLS.SNI
	}

	tconf := tls.Config{ServerName: *sni, NextProtos: []string{"h3"}, InsecureSkipVerify: conf.TLS.Insecure}
	var h3tr http3.Transport
	if conf.Noises.Enable {
		h3tr = http3.Transport{
			QUICConfig:      qc,
			TLSClientConfig: &tconf,
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udp, udpErr := net.ListenPacket("udp", "0.0.0.0:0")
				if udpErr != nil {
					return nil, udpErr
				}
				uaddr, uaddrErr := net.ResolveUDPAddr("udp", addr)
				if uaddrErr != nil {
					return nil, uaddrErr
				}
				// noise
				SendNoises(udp, uaddr, conf.Noises.Packets)
				return quic.Dial(
					ctx, udp, uaddr, tlsCfg, cfg,
				)
			},
		}
	} else {
		h3tr = http3.Transport{TLSClientConfig: &tconf}
	}
	return &http.Client{
		Transport: &h3tr,
	}
}

func utlsTransporter(conf *Conf, fingerprint utls.ClientHelloID, sni string, addr net.TCPAddr, fragment *Fragment) (*http.Client, error) {
	dialer := &net.Dialer{Timeout: time.Millisecond * time.Duration(conf.TLS.Utls.TcpTimeout)}

	var dialConn net.Conn
	var err error
	for reconnect := range conf.TLS.Utls.TcpConnectAttempt {
		dialConn, err = dialer.Dial("tcp", addr.String())
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
		} else {
			break
		}

		if reconnect+1 == conf.TLS.Utls.TcpConnectAttempt {
			return nil, err
		}
	}

	uTlsConf := utls.Config{InsecureSkipVerify: conf.TLS.Insecure}
	if strings.Contains(sni, "{ip}") {
		sni = addr.IP.String()
	}
	if sni != "" {
		uTlsConf.ServerName = sni
	}

	if conf.TLS.Utls.Fragment.Enable {
		dialConn = ConnWrap{
			fragment: fragment,
			conn:     dialConn,
			count:    0,
		}
	}

	uTlsConn := utls.UClient(dialConn, &uTlsConf, fingerprint)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(conf.Maxlatency))
	defer cancel()
	if err := uTlsConn.HandshakeContext(ctx); err != nil {
		uTlsConn.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s: UTLS handshake timeout", addr.String())
		}
		return nil, fmt.Errorf("%s: UTLS handshake error: %w", addr.String(), err)
	}

	if uTlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		return &http.Client{
			Transport: &http2.Transport{
				DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
					return uTlsConn, nil
				},
			},
		}, nil
	} else {
		return &http.Client{
			Transport: &http.Transport{
				DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return uTlsConn, nil
				},
			},
		}, nil
	}
}

func tlsTransporter(conf *Conf, sni *string) *http.Client {
	if sni == nil {
		sni = &conf.TLS.SNI
	}

	tr := http.Transport{
		TLSClientConfig: &tls.Config{ServerName: *sni, InsecureSkipVerify: conf.TLS.Insecure, NextProtos: conf.TLS.Alpn},
		Protocols:       &http.Protocols{},
	}
	tr.Protocols.SetHTTP1(true)
	tr.Protocols.SetHTTP2(true)

	return &http.Client{
		Transport: &tr,
	}
}
