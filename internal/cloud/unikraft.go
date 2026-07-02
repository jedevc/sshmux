package cloud

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"charm.land/log/v2"
	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
	"unikraft.com/cloud/sdk/platform"

	"sshmux/internal/config"
)

const (
	unikraftDefaultMetro      = "fra0"
	unikraftDefaultImage      = "jedevc/sshmux-guest:latest"
	unikraftDefaultMemoryMB   = 128
	unikraftDefaultSessionTTL = time.Minute
	unikraftTLSPort           = "2222"
	unikraftSSHPort           = 2222
)

type UnikraftProvider struct {
	client     platform.Client
	endpoint   string
	image      string
	memoryMB   int64
	sessionTTL time.Duration

	mu       sync.Mutex
	sessions map[string]*unikraftSession
}

type unikraftSession struct {
	uuid        string
	fqdn        string
	dialAddr    string
	hostKey     gossh.PublicKey
	authKey     gossh.Signer
	connections int
	expiresAt   *time.Time
}

func NewUnikraftProvider(entry config.CloudEntry) (*UnikraftProvider, error) {
	token := os.Getenv("UKC_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("UKC_TOKEN is required")
	}

	metro := cmp.Or(entry.Metro, os.Getenv("UKC_METRO"), unikraftDefaultMetro)
	image := cmp.Or(entry.Image, os.Getenv("UKC_IMAGE"), unikraftDefaultImage)
	memoryMB := entry.MemoryMB
	if memoryMB == 0 {
		memoryMB = unikraftDefaultMemoryMB
	}
	sessionTTL := entry.SessionTTL.Duration()
	if sessionTTL == 0 {
		sessionTTL = unikraftDefaultSessionTTL
	}

	provider := &UnikraftProvider{
		client: platform.NewClient(
			platform.WithToken(token),
			platform.WithDefaultMetro(metro),
			platform.WithHTTPClient(http.DefaultClient),
		),
		endpoint:   platform.EndpointForMetro(metro),
		image:      image,
		memoryMB:   memoryMB,
		sessionTTL: sessionTTL,
		sessions:   make(map[string]*unikraftSession),
	}
	go provider.reap()
	return provider, nil
}

func (p *UnikraftProvider) Dial(ctx context.Context, s ssh.Session) (*gossh.Client, func(), error) {
	username := s.User()
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		session, release, err := p.attach(ctx, username)
		if err != nil {
			return nil, nil, err
		}

		client, err := session.sshClient(ctx, username)
		if err != nil {
			release()
			p.removeIfSame(username, session)
			lastErr = err
			continue
		}

		cleanup := func() {
			_ = client.Close()
			release()
		}
		return client, cleanup, nil
	}
	return nil, nil, lastErr
}

func (p *UnikraftProvider) attach(ctx context.Context, username string) (*unikraftSession, func(), error) {
	var discard *unikraftSession

	p.mu.Lock()
	session, ok := p.sessions[username]
	if !ok {
		p.mu.Unlock()

		created, err := p.create(ctx, username)
		if err != nil {
			return nil, nil, err
		}

		p.mu.Lock()
		if existing, raced := p.sessions[username]; raced {
			session = existing
			discard = created
		} else {
			session = created
			p.sessions[username] = session
		}
	}

	session.connections++
	session.expiresAt = nil
	p.mu.Unlock()
	if discard != nil {
		log.Warn("unikraft: raced instance created; leaving it to guest idle timeout", "uuid", discard.uuid)
	}

	released := false
	release := func() {
		if released {
			return
		}
		released = true

		p.mu.Lock()
		defer p.mu.Unlock()

		current, ok := p.sessions[username]
		if !ok {
			return
		}
		current.connections--
		if current.connections <= 0 {
			current.connections = 0
			expiresAt := time.Now().Add(p.sessionTTL)
			current.expiresAt = &expiresAt
			log.Info("unikraft: session idle", "user", username, "expires_at", expiresAt)
		}
	}

	return session, release, nil
}

func (p *UnikraftProvider) create(ctx context.Context, username string) (*unikraftSession, error) {
	dialAddr, err := unikraftDialAddr(p.endpoint)
	if err != nil {
		return nil, err
	}

	hostKey, hostKeyPEM, err := generateHostKey()
	if err != nil {
		return nil, fmt.Errorf("generate guest host key: %w", err)
	}
	authKey, err := generateSSHSigner()
	if err != nil {
		return nil, fmt.Errorf("generate guest auth key: %w", err)
	}
	allowKey := string(gossh.MarshalAuthorizedKey(authKey.PublicKey()))

	autostart := true
	memoryMB := p.memoryMB
	port := uint32(unikraftSSHPort)
	timeoutS := int64(-1)
	resp, err := p.client.CreateInstance(ctx, platform.CreateInstanceRequest{
		Image:     &p.image,
		MemoryMb:  &memoryMB,
		Autostart: &autostart,
		TimeoutS:  &timeoutS,
		Env: map[string]string{
			"GUEST_HOST_KEY":     hostKeyPEM,
			"GUEST_ALLOW_KEY":    allowKey,
			"GUEST_IDLE_TIMEOUT": p.sessionTTL.String(),
		},
		Features: []platform.InstanceFeature{platform.InstanceFeatureDeleteOnStop},
		ServiceGroup: &platform.CreateInstanceRequestServiceGroup{
			Services: []platform.Service{
				{
					Port:            port,
					DestinationPort: &port,
					Handlers:        []platform.ConnectionHandler{platform.ConnectionHandlerTls},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unikraft create instance: %w", err)
	}
	if len(resp.Data.Instances) == 0 {
		return nil, fmt.Errorf("unikraft create instance: empty response")
	}

	inst := resp.Data.Instances[0]
	if inst.ServiceGroup == nil || len(inst.ServiceGroup.Domains) == 0 {
		return nil, fmt.Errorf("unikraft instance %s has no service group domains", inst.Uuid)
	}
	fqdn := inst.ServiceGroup.Domains[0].Fqdn
	if fqdn == "" {
		return nil, fmt.Errorf("unikraft instance %s service group domain FQDN is empty", inst.Uuid)
	}

	time.Sleep(500 * time.Millisecond)
	log.Info("unikraft: instance created", "user", username, "uuid", inst.Uuid, "fqdn", fqdn)
	return &unikraftSession{
		uuid:     inst.Uuid,
		fqdn:     fqdn,
		dialAddr: dialAddr,
		hostKey:  hostKey,
		authKey:  authKey,
	}, nil
}

func (p *UnikraftProvider) reap() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.reapOnce()
	}
}

func (p *UnikraftProvider) reapOnce() {
	now := time.Now()
	expired := make(map[string]*unikraftSession)

	p.mu.Lock()
	for username, session := range p.sessions {
		if session.connections == 0 && session.expiresAt != nil && now.After(*session.expiresAt) {
			expired[username] = session
			delete(p.sessions, username)
		}
	}
	p.mu.Unlock()

	for username, session := range expired {
		log.Info("unikraft: dropping idle instance from cache", "user", username, "uuid", session.uuid)
	}
}

func (p *UnikraftProvider) removeIfSame(username string, session *unikraftSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sessions[username] == session {
		delete(p.sessions, username)
		log.Info("unikraft: dropping stale instance from cache", "user", username, "uuid", session.uuid)
	}
}

func (s *unikraftSession) sshClient(ctx context.Context, username string) (*gossh.Client, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, "", &gossh.ClientConfig{
		User: username,
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(s.authKey),
		},
		HostKeyCallback: gossh.FixedHostKey(s.hostKey),
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake with unikraft guest: %w", err)
	}
	return gossh.NewClient(sshConn, chans, reqs), nil
}

func (s *unikraftSession) dial(ctx context.Context) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         s.fqdn,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // UKC service-group TLS uses SNI routing with internal certificates.
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", s.dialAddr)
	if err != nil {
		return nil, fmt.Errorf("tls dial unikraft endpoint %s (sni=%s): %w", s.dialAddr, s.fqdn, err)
	}
	return conn, nil
}

func unikraftDialAddr(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse unikraft endpoint %q: %w", endpoint, err)
	}
	dialHost := u.Hostname()
	if dialHost == "" {
		return "", fmt.Errorf("unikraft endpoint %q has no hostname", endpoint)
	}
	dialPort := u.Port()
	if dialPort == "" {
		dialPort = unikraftTLSPort
	}
	return net.JoinHostPort(dialHost, dialPort), nil
}

func generateSSHSigner() (gossh.Signer, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return gossh.NewSignerFromKey(privKey)
}

func generateHostKey() (gossh.PublicKey, string, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	signer, err := gossh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, "", err
	}
	pemBlock, err := gossh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, "", err
	}
	return signer.PublicKey(), string(pem.EncodeToMemory(pemBlock)), nil
}
