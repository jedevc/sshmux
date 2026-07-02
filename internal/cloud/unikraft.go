package cloud

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"charm.land/log/v2"
	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
	"unikraft.com/cloud/sdk/platform"

	"sshmux/internal/config"
)

const (
	unikraftDefaultMetro    = "fra"
	unikraftDefaultImage    = "jedevc/sshmux-guest:latest"
	unikraftDefaultMemoryMB = 32
	unikraftDefaultIdleTTL  = time.Minute
	unikraftInstancePrefix  = "sshmux-"
	unikraftReadyTimeout    = 30 * time.Second
	unikraftReadyBackoff    = 500 * time.Millisecond
	unikraftTLSPort         = "2222"
	unikraftSSHPort         = 2222
)

type UnikraftProvider struct {
	client   platform.Client
	endpoint string
	image    string
	memoryMB int64
	idleTTL  time.Duration
	maxInst  int
	seed     [32]byte
}

type unikraftInstance struct {
	uuid     string
	fqdn     string
	dialAddr string
	hostKey  gossh.PublicKey
	authKey  gossh.Signer
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
	idleTTL := entry.SessionTTL.Duration()
	if idleTTL == 0 {
		idleTTL = unikraftDefaultIdleTTL
	}

	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("generate unikraft provider seed: %w", err)
	}

	provider := &UnikraftProvider{
		client: platform.NewClient(
			platform.WithToken(token),
			platform.WithDefaultMetro(metro),
			platform.WithHTTPClient(http.DefaultClient),
		),
		endpoint: platform.EndpointForMetro(metro),
		image:    image,
		memoryMB: memoryMB,
		idleTTL:  idleTTL,
		maxInst:  entry.MaxInstances,
		seed:     seed,
	}
	return provider, nil
}

func (p *UnikraftProvider) Dial(ctx context.Context, s ssh.Session) (*gossh.Client, func(), error) {
	username := s.User()
	name := p.instanceName(username)
	deadline := time.NewTimer(unikraftReadyTimeout)
	defer deadline.Stop()

	var lastErr error
	for {
		inst, err := p.getOrCreate(ctx, name, username)
		if err != nil {
			return nil, nil, err
		}

		client, err := inst.sshClient(ctx, username)
		if err != nil {
			lastErr = err
			if !isRetryableUnikraftDial(err) {
				return nil, nil, err
			}
			select {
			case <-ctx.Done():
				return nil, nil, fmt.Errorf("wait for unikraft guest ssh: %w", ctx.Err())
			case <-deadline.C:
				return nil, nil, lastErr
			case <-time.After(unikraftReadyBackoff):
			}
			continue
		}

		cleanup := func() {
			_ = client.Close()
		}
		return client, cleanup, nil
	}
}

func (p *UnikraftProvider) getOrCreate(ctx context.Context, name string, username string) (*unikraftInstance, error) {
	inst, err := p.lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	if inst != nil {
		return inst, nil
	}
	if err := p.checkInstanceLimit(ctx); err != nil {
		return nil, err
	}

	inst, err = p.create(ctx, name, username)
	if err == nil {
		return inst, nil
	}
	if !platform.ErrorContains(err, platform.APIHTTPErrorAlreadyExists) {
		return nil, err
	}

	inst, lookupErr := p.lookup(ctx, name)
	if lookupErr != nil {
		return nil, lookupErr
	}
	if inst == nil {
		return nil, err
	}
	return inst, nil
}

func (p *UnikraftProvider) lookup(ctx context.Context, name string) (*unikraftInstance, error) {
	details := true
	resp, err := p.client.GetInstances(ctx, []platform.NameOrUUID{{Name: &name}}, platform.GetInstancesOpts{Details: &details})
	if err != nil {
		if platform.ErrorContains(err, platform.APIHTTPErrorNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("unikraft get instance %s: %w", name, err)
	}
	if resp == nil || resp.Data == nil || len(resp.Data.Instances) == 0 {
		return nil, nil
	}
	return p.instanceFromPlatform(resp.Data.Instances[0])
}

func (p *UnikraftProvider) checkInstanceLimit(ctx context.Context) error {
	if p.maxInst <= 0 {
		return nil
	}
	resp, err := p.client.GetInstances(ctx, nil, platform.GetInstancesOpts{})
	if err != nil {
		return fmt.Errorf("unikraft count instances: %w", err)
	}
	if resp == nil || resp.Data == nil {
		return nil
	}

	total := 0
	for _, inst := range resp.Data.Instances {
		if strings.HasPrefix(inst.Name, unikraftInstancePrefix) {
			total++
		}
	}
	if total >= p.maxInst {
		return fmt.Errorf("unikraft instance limit reached: %d/%d", total, p.maxInst)
	}
	return nil
}

func (p *UnikraftProvider) create(ctx context.Context, name string, username string) (*unikraftInstance, error) {
	_, hostKeyPEM, err := p.deriveHostKey(name)
	if err != nil {
		return nil, fmt.Errorf("derive guest host key: %w", err)
	}
	authKey, err := p.deriveSSHSigner("auth", name)
	if err != nil {
		return nil, fmt.Errorf("derive guest auth key: %w", err)
	}
	allowKey := string(gossh.MarshalAuthorizedKey(authKey.PublicKey()))

	autostart := true
	memoryMB := p.memoryMB
	port := uint32(unikraftSSHPort)
	timeoutS := int64(-1)
	resp, err := p.client.CreateInstance(ctx, platform.CreateInstanceRequest{
		Name:      &name,
		Image:     &p.image,
		MemoryMb:  &memoryMB,
		Autostart: &autostart,
		TimeoutS:  &timeoutS,
		Env: map[string]string{
			"GUEST_HOST_KEY":     hostKeyPEM,
			"GUEST_ALLOW_KEY":    allowKey,
			"GUEST_IDLE_TIMEOUT": p.idleTTL.String(),
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
	if resp == nil || resp.Data == nil || len(resp.Data.Instances) == 0 {
		return nil, fmt.Errorf("unikraft create instance: empty response")
	}

	inst := resp.Data.Instances[0]
	log.Info("unikraft: instance created", "user", username, "name", name, "uuid", inst.Uuid)
	return p.instanceFromPlatform(inst)
}

func (p *UnikraftProvider) instanceFromPlatform(inst platform.Instance) (*unikraftInstance, error) {
	if inst.ServiceGroup == nil || len(inst.ServiceGroup.Domains) == 0 {
		return nil, fmt.Errorf("unikraft instance %s has no service group domains", inst.Uuid)
	}
	fqdn := inst.ServiceGroup.Domains[0].Fqdn
	if fqdn == "" {
		return nil, fmt.Errorf("unikraft instance %s service group domain FQDN is empty", inst.Uuid)
	}
	dialAddr, err := unikraftDialAddr(p.endpoint)
	if err != nil {
		return nil, err
	}
	hostKey, _, err := p.deriveHostKey(inst.Name)
	if err != nil {
		return nil, fmt.Errorf("derive guest host key: %w", err)
	}
	authKey, err := p.deriveSSHSigner("auth", inst.Name)
	if err != nil {
		return nil, fmt.Errorf("derive guest auth key: %w", err)
	}
	return &unikraftInstance{
		uuid:     inst.Uuid,
		fqdn:     fqdn,
		dialAddr: dialAddr,
		hostKey:  hostKey,
		authKey:  authKey,
	}, nil
}

func (s *unikraftInstance) sshClient(ctx context.Context, username string) (*gossh.Client, error) {
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

func (s *unikraftInstance) dial(ctx context.Context) (net.Conn, error) {
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

func isRetryableUnikraftDial(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset")
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

func (p *UnikraftProvider) instanceName(username string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"sshmux", p.endpoint, p.image, username}, "\x00")))
	return unikraftInstancePrefix + hex.EncodeToString(sum[:16])
}

func (p *UnikraftProvider) deriveSSHSigner(label string, name string) (gossh.Signer, error) {
	mac := hmac.New(sha256.New, p.seed[:])
	_, _ = mac.Write([]byte("sshmux/unikraft/" + label + "/" + name))
	seed := mac.Sum(nil)
	return gossh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]))
}

func (p *UnikraftProvider) deriveHostKey(name string) (gossh.PublicKey, string, error) {
	mac := hmac.New(sha256.New, p.seed[:])
	_, _ = mac.Write([]byte("sshmux/unikraft/host/" + name))
	seed := mac.Sum(nil)
	privKey := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
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
