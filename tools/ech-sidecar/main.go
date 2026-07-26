// Command ech-sidecar is a terminating, fail-closed Encrypted Client Hello (ECH)
// re-originator for MessageFoundry (ASVS 12.1.5 — protect against SNI leakage).
//
// It listens on a loopback HTTP port as a forward proxy. For each request it:
//   - determines the upstream host (absolute-form request URI, else the Host header),
//   - resolves that host's ECHConfigList from its DNS HTTPS record (RR type 65)
//     over DoH (application/dns-json), extracting SvcParamKey 5 (ech) by walking
//     the SvcParams in the record's RDATA,
//   - dials the upstream with crypto/tls using EncryptedClientHelloConfigList so the
//     real SNI travels only inside the encrypted ClientHelloInner,
//   - verifies the upstream certificate normally (verification is NEVER disabled),
//   - re-issues the HTTP request over that connection and streams the response back.
//
// FAIL-CLOSED: if the upstream publishes no ECHConfig, or the TLS server does not
// accept ECH (ConnectionState.ECHAccepted == false), the request is REFUSED with a
// 502 — the sidecar never silently falls back to a cleartext-SNI connection.
//
// stdlib-only; no module dependencies; builds offline (GOPROXY=off).
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const dohURL = "https://cloudflare-dns.com/dns-query"

// hop-by-hop headers that must not be forwarded (RFC 7230 §6.1).
var hopByHop = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8123", "loopback listen address (host:port)")
	timeout := flag.Duration("timeout", 30*time.Second, "per-request upstream timeout")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("bad -addr %q: %v", *addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to bind non-loopback address %q (ECH sidecar is loopback-only)", *addr)
	}

	h := &handler{timeout: *timeout}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
	}
	log.Printf("ech-sidecar: fail-closed ECH re-originator listening on http://%s", *addr)
	log.Fatal(srv.ListenAndServe())
}

type handler struct {
	timeout time.Duration
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CONNECT tunnels would give end-to-end TLS the sidecar cannot originate ECH
	// into — reject explicitly rather than proxy blindly.
	if r.Method == http.MethodConnect {
		http.Error(w, "ech-sidecar does not support CONNECT tunnels; send an absolute-form request or set the Host header", http.StatusMethodNotAllowed)
		return
	}

	// Upstream host: prefer the absolute-form request URI (classic forward proxy),
	// fall back to the Host header (plain http://sidecar/path + Host: upstream).
	hostport := r.URL.Host
	if hostport == "" {
		hostport = r.Host
	}
	if hostport == "" {
		http.Error(w, "no upstream host (absolute-form URI or Host header required)", http.StatusBadRequest)
		return
	}
	hostname, port := hostport, "443"
	if hh, pp, err := net.SplitHostPort(hostport); err == nil {
		hostname, port = hh, pp
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	echList, err := resolveECH(ctx, hostname)
	if err != nil {
		// FAIL-CLOSED: no ECHConfig -> refuse, do not connect in the clear.
		http.Error(w, "ech-sidecar refusing (fail-closed): "+err.Error(), http.StatusBadGateway)
		log.Printf("REFUSE %s: %v", hostname, err)
		return
	}

	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 15 * time.Second}
			raw, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{
				ServerName:                     hostname, // encrypted inside ClientHelloInner
				EncryptedClientHelloConfigList: echList,
				MinVersion:                     tls.VersionTLS13,
				// InsecureSkipVerify stays false — the upstream cert is verified.
			}
			tc := tls.Client(raw, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, fmt.Errorf("tls handshake to %s: %w", hostname, err)
			}
			// FAIL-CLOSED second gate: even with a config list, if the server did
			// not accept ECH the real SNI may have leaked — refuse the connection.
			if !tc.ConnectionState().ECHAccepted {
				tc.Close()
				return nil, fmt.Errorf("ECH not accepted by %s — refusing (fail-closed)", hostname)
			}
			return tc, nil
		},
	}
	defer transport.CloseIdleConnections()

	outURL := &url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(hostname, port),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad upstream request: "+err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	outReq.Host = hostname

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "ech-sidecar upstream error: "+err.Error(), http.StatusBadGateway)
		log.Printf("UPSTREAM %s: %v", hostname, err)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("X-ECH-Sidecar", "ech-accepted")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	log.Printf("OK %s %s -> %d (ECH accepted)", r.Method, hostname, resp.StatusCode)
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// resolveECH queries the DNS HTTPS record (type 65) for host over DoH and returns
// the ECHConfigList bytes from SvcParamKey 5. It returns an error (never a nil,
// nil "no ECH but ok") so callers fail closed.
func resolveECH(ctx context.Context, host string) ([]byte, error) {
	q := dohURL + "?name=" + url.QueryEscape(host) + "&type=65"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH query for %s: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH query for %s: status %d", host, resp.StatusCode)
	}
	var out struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode DoH JSON for %s: %w", host, err)
	}
	for _, a := range out.Answer {
		if a.Type != 65 { // HTTPS RR
			continue
		}
		ech, err := extractECH(a.Data)
		if err != nil {
			continue
		}
		if len(ech) > 0 {
			return ech, nil
		}
	}
	return nil, fmt.Errorf("no ECHConfig (HTTPS/SvcParamKey 5) published for %s", host)
}

// extractECH pulls the ech SvcParamValue (SvcParamKey 5) out of an HTTPS RR's
// RDATA as returned by DoH JSON. Cloudflare returns type-65 RDATA in RFC 3597
// generic form: `\# <len> <hex...>`. We hex-decode the RDATA and walk the
// SvcParams. As a fallback we also accept presentation form containing an
// `ech="<base64>"` token.
func extractECH(data string) ([]byte, error) {
	data = strings.TrimSpace(data)
	if strings.HasPrefix(data, `\#`) {
		fields := strings.Fields(data) // ["\#", "<len>", "<hex>", ...]
		if len(fields) < 2 {
			return nil, errors.New("malformed generic RDATA")
		}
		rdata, err := hex.DecodeString(strings.Join(fields[2:], ""))
		if err != nil {
			return nil, fmt.Errorf("hex RDATA: %w", err)
		}
		return walkSvcParamsForECH(rdata)
	}
	// Presentation-form fallback: find ech="..." (or ech=...).
	if i := strings.Index(data, "ech="); i >= 0 {
		rest := data[i+len("ech="):]
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, `"`) {
			if j := strings.Index(rest[1:], `"`); j >= 0 {
				rest = rest[1 : 1+j]
			}
		} else if sp := strings.IndexAny(rest, " \t"); sp >= 0 {
			rest = rest[:sp]
		}
		b, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return nil, fmt.Errorf("base64 ech value: %w", err)
		}
		return b, nil
	}
	return nil, errors.New("no ech SvcParam in RDATA")
}

// walkSvcParamsForECH parses SVCB/HTTPS RDATA: SvcPriority(2) + TargetName(domain)
// + SvcParams(key(2) len(2) value(len))*, returning the value for key 5 (ech).
func walkSvcParamsForECH(rdata []byte) ([]byte, error) {
	pos := 0
	if len(rdata) < 2 {
		return nil, errors.New("RDATA too short for SvcPriority")
	}
	pos += 2 // SvcPriority

	// TargetName: length-prefixed labels ending in a zero-length root label.
	for {
		if pos >= len(rdata) {
			return nil, errors.New("RDATA truncated in TargetName")
		}
		l := int(rdata[pos])
		pos++
		if l == 0 {
			break // root label
		}
		if l&0xC0 != 0 { // no compression pointers in HTTPS RDATA
			return nil, errors.New("unexpected compression in TargetName")
		}
		pos += l
	}

	for pos+4 <= len(rdata) {
		key := int(rdata[pos])<<8 | int(rdata[pos+1])
		plen := int(rdata[pos+2])<<8 | int(rdata[pos+3])
		pos += 4
		if pos+plen > len(rdata) {
			return nil, errors.New("RDATA truncated in SvcParam value")
		}
		val := rdata[pos : pos+plen]
		pos += plen
		if key == 5 { // ech
			out := make([]byte, len(val))
			copy(out, val)
			return out, nil
		}
	}
	return nil, errors.New("no ech SvcParam (key 5)")
}
