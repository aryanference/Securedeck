package gateway

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// Proxy is a transparent HTTP/HTTPS forward proxy for sidecar mode. The
// agent's outbound traffic is routed through it (via iptables/network
// config, outside the scope of this package); no code changes to the agent
// are required. Every request is checked against the enforcer before being
// forwarded.
type Proxy struct {
	enforcer *Enforcer
}

func NewProxy(enforcer *Enforcer) *Proxy {
	return &Proxy{enforcer: enforcer}
}

// ServeHTTP implements http.Handler. Plain HTTP requests are enforced and
// forwarded directly; CONNECT requests (HTTPS tunneling) are enforced against
// the SNI/authority before the tunnel is established, then the bytes are
// relayed opaquely — the proxy never terminates TLS itself.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	agentToken := extractAgentToken(r)

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, agentToken)
		return
	}
	p.handleForward(w, r, agentToken)
}

// extractAgentToken pulls the agent's PASETO token from the proxy
// authentication header. Sidecar deployments configure the agent's HTTP
// client (or an injected credential helper) to set this header.
func extractAgentToken(r *http.Request) string {
	if tok := r.Header.Get("Proxy-Authorization"); tok != "" {
		return tok
	}
	return r.Header.Get("X-Securedeck-Agent-Token")
}

func (p *Proxy) handleForward(w http.ResponseWriter, r *http.Request, token string) {
	decision := p.enforcer.Enforce(r.Context(), ActionRequest{
		Token:      token,
		ActionType: "http_request",
		Target:     r.URL.String(),
	})

	if !decision.Allowed {
		writeDenied(w, decision)
		return
	}

	// Forward the request to its original destination.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("X-Securedeck-Agent-Token")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Securedeck-Decision-Id", decision.DecisionID)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request, token string) {
	// r.Host is the CONNECT authority, e.g. "api.example.com:443" — this is
	// what we check against the egress allowlist since we never see the
	// inner TLS handshake's SNI in a pure TCP tunnel without termination.
	decision := p.enforcer.Enforce(r.Context(), ActionRequest{
		Token:      token,
		ActionType: "http_request",
		Target:     "https://" + r.Host,
	})

	if !decision.Allowed {
		writeDenied(w, decision)
		return
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "failed to reach upstream", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		io.Copy(destConn, clientConn)
	}()
	io.Copy(clientConn, destConn)
}

func writeDenied(w http.ResponseWriter, decision *Decision) {
	w.Header().Set("X-Securedeck-Decision-Id", decision.DecisionID)
	w.Header().Set("X-Securedeck-Deny-Reason", decision.Reason)
	http.Error(w, "forbidden: "+decision.Reason, http.StatusForbidden)
}

// NewListener starts the proxy on addr. Kept separate from ServeHTTP so
// tests can drive the handler directly with httptest.
func (p *Proxy) NewListener(addr string) (net.Listener, *http.Server, error) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	return lis, srv, nil
}

var _ = log.Printf // reserved for future structured request logging
