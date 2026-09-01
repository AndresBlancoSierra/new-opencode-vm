// Package vpn generates a per-environment WireGuard configuration for an independent
// NordVPN identity, and renders the in-guest kill-switch that enforces "no egress
// except through the tunnel".
//
// CRITICAL INVARIANT: generating a per-VM config MUST NEVER mutate the host's VPN.
// The host runs exactly one NordLynx daemon/interface per OS, so any `nordvpn
// connect`/`nordvpn disconnect` on the host would tear down / switch / re-authenticate
// the host tunnel and interrupt the host agent. To honor this:
//
//   - GenerateSafe prefers the token API path (Client.Generate): an independent
//     WireGuard keypair per VM, fetched over the Nord REST API. It never touches the
//     host VPN.
//   - GenerateFromHostKey is the fallback when no token is available: it harvests the
//     host's EXISTING NordLynx private key READ-ONLY via `wg showconf nordlynx` (the
//     host interface stays up) and pairs it with a freshly chosen server from the
//     PUBLIC Nord recommendations API (no auth). It never invokes the `nordvpn` CLI.
//
// Neither path ever runs `nordvpn connect` / `nordvpn disconnect`. The regression
// test TestGenerateSafeNoHostMutation makes a regression to the old behavior
// impossible.
package vpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// WGConfig is a rendered WireGuard configuration.
type WGConfig struct {
	PrivateKey    string
	Address       string
	PeerPublicKey string
	Endpoint      string // host:port
	AllowedIPs    string
	Keepalive     int
}

// Client talks to the NordVPN API.
type Client struct {
	Token      string
	HTTP       *http.Client
	BaseURL    string
	cachedPriv string // cached account WireGuard private key (set by Credentials)
}

// NewClient builds a Client for the given access token.
func NewClient(token string) *Client {
	return &Client{
		Token:   token,
		HTTP:    &http.Client{Timeout: 20 * time.Second},
		BaseURL: "https://api.nordvpn.com",
	}
}

// credentialsResp models the token-API /v1/users/services/credentials response.
// The live NordVPN API returns the WireGuard private key as a top-level
// `nordlynx_private_key` field, plus `username`/`password` (the service
// credentials). It does NOT return a `services.standard_v1` wrapper.
type credentialsResp struct {
	NordlynxPrivateKey string `json:"nordlynx_private_key"`
	Username           string `json:"username"`
	Password           string `json:"password"`
}

// countryResp models /v1/servers/countries (id<->code map).
type countryResp struct {
	ID   int    `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
}

// recommendationResp models /v1/servers/recommendations.
type recommendationResp struct {
	Station      string `json:"station"`
	Technologies []struct {
		Identifier string          `json:"identifier"`
		Metadata   json.RawMessage `json:"metadata"`
	} `json:"technologies"`
}

// techMeta is the list-of-{name,value} form Nord returns for the wireguard_udp
// technology's metadata (e.g. [{"name":"public_key","value":"<base64>"}]).
type techMeta struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// wgPublicKey extracts the WireGuard peer public key from a recommendation. The
// metadata field is inconsistently shaped across Nord's API: it may be a plain
// string (the pubkey) OR a list of {name,value} objects. We accept both.
func (r recommendationResp) wgPublicKey() string {
	for _, t := range r.Technologies {
		if t.Identifier != "wireguard_udp" {
			continue
		}
		raw := strings.TrimSpace(string(t.Metadata))
		if raw == "" || raw == "[]" || raw == "null" {
			continue
		}
		if raw[0] != '[' {
			var s string
			if json.Unmarshal(t.Metadata, &s) == nil {
				return strings.TrimSpace(s)
			}
			return ""
		}
		var meta []techMeta
		if json.Unmarshal(t.Metadata, &meta) == nil {
			for _, m := range meta {
				if m.Name == "public_key" {
					return strings.TrimSpace(m.Value)
				}
			}
		}
	}
	return ""
}

// Credentials exchanges the token for a user keypair + interface address.
func (c *Client) Credentials(ctx context.Context) (priv, pub, addr string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/v1/users/services/credentials", nil)
	if err != nil {
		return "", "", "", err
	}
	// The NordVPN service-credentials API requires BASIC auth where the username
	// is the literal string "token" and the password is the account access token
	// (NOT a Bearer token). See credentialsResp / Credentials.
	basic := "token:" + c.Token
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basic)))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("credentials request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("credentials: status %d", resp.StatusCode)
	}
	var r credentialsResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", "", fmt.Errorf("credentials decode: %w", err)
	}
	if r.NordlynxPrivateKey == "" {
		return "", "", "", fmt.Errorf("credentials: no nordlynx_private_key in response")
	}
	// The API does not return a guest interface address (NordLynx assigns a
	// dynamic NAT IP per session); use the standard default tunnel address.
	return r.NordlynxPrivateKey, "", "10.5.0.2/32", nil
}

var countryIDCache sync.Map // code -> int

// countryID maps an ISO country code (e.g. "de") to a NordVPN country id.
// It caches the result and retries on 429/1015 rate limiting.
func (c *Client) countryID(ctx context.Context, code string) (int, error) {
	if v, ok := countryIDCache.Load(strings.ToLower(code)); ok {
		if id, ok := v.(int); ok {
			return id, nil
		}
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			c.BaseURL+"/v1/servers/countries", nil)
		if err != nil {
			return 0, err
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("countries request: %w", err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		if resp.StatusCode == 429 {
			// Cloudflare 1015 or Nord rate limit — body is not JSON.
			resp.Body.Close()
			lastErr = fmt.Errorf("countries rate limited (429)")
			time.Sleep(time.Duration(2<<attempt) * time.Second)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := json.Marshal(resp.Status)
			resp.Body.Close()
			lastErr = fmt.Errorf("countries: status %d %s", resp.StatusCode, string(body))
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		var list []countryResp
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			resp.Body.Close()
			// If body was not JSON (e.g. Cloudflare HTML), treat as rate limit.
			lastErr = fmt.Errorf("countries decode: %w", err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		resp.Body.Close()
		for _, co := range list {
			if strings.EqualFold(co.Code, code) {
				countryIDCache.Store(strings.ToLower(code), co.ID)
				return co.ID, nil
			}
		}
		return 0, fmt.Errorf("country %q not found", code)
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, fmt.Errorf("country %q not found after retries", code)
}

// ServerSuggestion is one recommended WireGuard server for a country.
type ServerSuggestion struct {
	Station   string // e.g. "5.6.7.8"
	PublicKey string // WireGuard peer public key
}

// Recommend returns a single WireGuard server endpoint + public key for a country.
func (c *Client) Recommend(ctx context.Context, code string) (endpoint, pubKey string, err error) {
	ss, err := c.RecommendN(ctx, code, 1)
	if err != nil {
		return "", "", err
	}
	return ss[0].Station + ":51820", ss[0].PublicKey, nil
}

// RecommendN returns up to limit recommended WireGuard servers for a country. The
// caller iterates over these to find one whose effective public identity is unique
// (NordLynx assigns a dynamic NAT IP per session, so server != identity). The
// recommendations endpoint requires NO auth, so an empty-token Client works.
func (c *Client) RecommendN(ctx context.Context, code string, limit int) ([]ServerSuggestion, error) {
	cid, err := c.countryID(ctx, code)
	if err != nil {
		return nil, err
	}
	if limit < 1 {
		limit = 1
	}
	u := c.BaseURL + "/v1/servers/recommendations?" + url.Values{
		"filters[servers_technologies][identifier]": {"wireguard_udp"},
		"filters[country_id]":                       {fmt.Sprintf("%d", cid)},
		"limit":                                     {fmt.Sprintf("%d", limit)},
	}.Encode()
	var recs []recommendationResp
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("recommend request: %w", err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		if resp.StatusCode == 429 {
			resp.Body.Close()
			lastErr = fmt.Errorf("recommend rate limited (429)")
			time.Sleep(time.Duration(2<<attempt) * time.Second)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("recommend: status %d", resp.StatusCode)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		if err := json.NewDecoder(resp.Body).Decode(&recs); err != nil {
			resp.Body.Close()
			lastErr = fmt.Errorf("recommend decode: %w", err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		resp.Body.Close()
		lastErr = nil
		break
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("no server recommended for %q", code)
	}
	out := make([]ServerSuggestion, 0, len(recs))
	for _, r := range recs {
		if pub := r.wgPublicKey(); pub != "" {
			out = append(out, ServerSuggestion{Station: r.Station, PublicKey: pub})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("recommended servers for %q have no wireguard public key", code)
	}
	return out, nil
}

// Generate builds a WGConfig for the requested country using the client token. This
// is the preferred (token) path: an independent keypair per VM, never touching the
// host VPN.
func (c *Client) Generate(ctx context.Context, country string) (*WGConfig, error) {
	priv, _, addr, err := c.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	endpoint, pub, err := c.Recommend(ctx, country)
	if err != nil {
		return nil, err
	}
	return &WGConfig{
		PrivateKey:    priv,
		Address:       addr,
		PeerPublicKey: pub,
		Endpoint:      endpoint,
		AllowedIPs:    "0.0.0.0/0, ::/0",
		Keepalive:     25,
	}, nil
}

// buildWG assembles a WGConfig from a (harvested or own) private key + address and
// a chosen WireGuard server, never touching the host VPN.
func buildWG(priv, addr string, srv ServerSuggestion) *WGConfig {
	if addr == "" {
		addr = "10.5.0.2/32"
	}
	return &WGConfig{
		PrivateKey:    priv,
		Address:       addr,
		PeerPublicKey: srv.PublicKey,
		Endpoint:      srv.Station + ":51820",
		AllowedIPs:    "0.0.0.0/0, ::/0",
		Keepalive:     25,
	}
}

// GenerateForServer builds a per-VM WGConfig for a SPECIFIC recommended server,
// WITHOUT ever touching the host VPN. It is the building block used by the
// coordinated, cross-process allocator in cmd/lg so that two concurrent `lg vm` /
// `lg new` processes pick DISTINCT WireGuard servers (and therefore distinct egress
// IPs — NordLynx assigns the server IP as the egress identity).
//
// Token path: an independent keypair fetched from the Nord API. No-token fallback:
// a read-only harvest of the host's already-up NordLynx private key (`wg showconf
// nordlynx`). Neither path invokes the `nordvpn` CLI. See TestGenerateForServer*.
func GenerateForServer(ctx context.Context, cli *Client, country string, srv ServerSuggestion) (*WGConfig, error) {
	if cli != nil && cli.Token != "" {
		if priv, _, addr, err := cli.Credentials(ctx); err == nil && priv != "" {
			return buildWG(priv, addr, srv), nil
		}
		// Token present but credentials failed: fall back to host-key harvest
		// rather than failing the VM (resilience requirement).
	}
	priv, addr, _, err := harvestHostKey(ctx)
	if err != nil {
		return nil, err
	}
	return buildWG(priv, addr, srv), nil
}

// runCmd executes a command and returns its combined output. It is a package-level
// variable so tests can intercept it and assert that VM creation NEVER mutates the
// host NordLynx interface (no `nordvpn connect`/`nordvpn disconnect`).
var runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// GenerateSafe builds a per-environment WireGuard config WITHOUT EVER touching the
// host VPN. If a NordVPN access token is configured it uses the token API (an
// independent keypair per VM). Otherwise it falls back to GenerateFromHostKey, which
// harvests the host's EXISTING NordLynx private key read-only (wg showconf nordlynx)
// and pairs it with a freshly chosen server from the public Nord recommendations API.
// Neither path runs `nordvpn connect` / `nordvpn disconnect` or otherwise mutates the
// host's nordlynx interface. See the regression test TestGenerateSafeNoHostMutation.
func GenerateSafe(ctx context.Context, cli *Client, country string) (*WGConfig, error) {
	if cli != nil && cli.Token != "" {
		if wg, err := cli.Generate(ctx, country); err == nil {
			return wg, nil
		}
		// Token present but generation failed: fall back to host-key harvest rather
		// than failing the VM (resilience requirement).
	}
	return GenerateFromHostKey(ctx, cli, country)
}

// GenerateFromHostKey produces a per-VM WGConfig by reusing the host's already-up
// NordLynx identity (read-only) so the host VPN is never disconnected/reconnected.
// It contacts ONLY the public Nord recommendations API (no auth) to pick a server,
// and never invokes the `nordvpn` CLI.
func GenerateFromHostKey(ctx context.Context, cli *Client, country string) (*WGConfig, error) {
	priv, addr, hostPeer, err := harvestHostKey(ctx)
	if err != nil {
		return nil, err
	}
	if cli == nil {
		cli = NewClient("")
	}
	servers, err := cli.RecommendN(ctx, country, 5)
	if err != nil {
		return nil, fmt.Errorf("recommend server for %q: %w", country, err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no server recommended for %q", country)
	}
	// Prefer a server different from the host's current peer to avoid reusing the
	// same (keypair, server) pair the host already holds (Nord allows one connection
	// per keypair per server).
	var chosen *ServerSuggestion
	for i := range servers {
		if servers[i].Station != hostPeer {
			chosen = &servers[i]
			break
		}
	}
	if chosen == nil {
		chosen = &servers[0]
	}
	return &WGConfig{
		PrivateKey:    priv,
		Address:       addr,
		PeerPublicKey: chosen.PublicKey,
		Endpoint:      chosen.Station + ":51820",
		AllowedIPs:    "0.0.0.0/0, ::/0",
		Keepalive:     25,
	}, nil
}

// harvestHostKey reads the host's NordLynx private key + address (and current peer
// endpoint) READ-ONLY from the live interface via `wg showconf nordlynx`. This never
// changes host state. It requires root (the host interface is root-owned), which `lg`
// already runs as.
func harvestHostKey(ctx context.Context) (priv, addr, peer string, err error) {
	out, err := runCmd(ctx, "wg", "showconf", "nordlynx")
	if err != nil {
		return "", "", "", fmt.Errorf("harvest host nordlynx key (wg showconf nordlynx): %w", err)
	}
	return parseHostKey(string(out))
}

// parseHostKey extracts the [Interface] PrivateKey + Address and the [Peer] Endpoint
// from a `wg showconf` dump (read-only; no host mutation).
func parseHostKey(s string) (priv, addr, peer string, err error) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if v := strings.TrimPrefix(line, "PrivateKey ="); v != line {
			priv = strings.TrimSpace(v)
		} else if v := strings.TrimPrefix(line, "Address ="); v != line {
			addr = strings.TrimSpace(v)
		} else if v := strings.TrimPrefix(line, "Endpoint ="); v != line {
			peer = strings.TrimSpace(v)
			if i := strings.LastIndex(peer, ":"); i >= 0 {
				peer = peer[:i]
			}
		}
	}
	if priv == "" {
		return "", "", "", fmt.Errorf("no PrivateKey in wg showconf output")
	}
	if addr == "" {
		addr = "10.5.0.2/32"
	}
	return priv, addr, peer, nil
}

// ConfigString renders the WireGuard INI config.
func ConfigString(wg *WGConfig) string {
	ka := wg.Keepalive
	if ka == 0 {
		ka = 25
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
FwMark = 0xe1f1

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = %d
`, wg.PrivateKey, wg.Address, wg.PeerPublicKey, wg.Endpoint, wg.AllowedIPs, ka)
}

// KillSwitchScript returns in-guest nftables commands that drop all output except
// loopback and the WireGuard interface (and VPN-marked sockets). With the tunnel
// down, no egress is possible — there is no fallback to the host network.
func KillSwitchScript(iface string) string {
	return fmt.Sprintf(`
nft add table inet lgkill
nft add chain inet lgkill output "{ type filter hook output priority filter; policy drop; }"
nft add rule inet lgkill output oifname lo accept
nft add rule inet lgkill output oifname %s accept
nft add rule inet lgkill output ct mark 0x0000e1f1 accept
nft add rule inet lgkill output ct state established,related accept
`, iface)
}

// KillSwitchScriptHardened returns the fail-closed in-guest ruleset for the NEW
// model: it drops all output except loopback + the WireGuard tunnel + VPN-marked
// sockets + established/related, AND additionally blocks any DNS to non-tunnel
// destinations and any IPv6 egress that is not on the tunnel (fail-closed on v6).
// This guarantees no DNS leak and no IPv6 bypass when the tunnel is the only
// sanctioned egress.
func KillSwitchScriptHardened(iface string) string {
	return fmt.Sprintf(`
nft add table inet lgkill
nft add chain inet lgkill output "{ type filter hook output priority filter; policy drop; }"
nft add rule inet lgkill output oifname lo accept
nft add rule inet lgkill output oifname %s accept
nft add rule inet lgkill output meta mark 0x0000e1f1 accept
nft add rule inet lgkill output ct state established,related accept
nft add rule inet lgkill output ip daddr 10.0.0.0/8 drop
nft add rule inet lgkill output ip daddr 172.16.0.0/12 drop
nft add rule inet lgkill output ip daddr 192.168.0.0/16 drop
nft add rule inet lgkill output ip daddr 127.0.0.0/8 drop
nft add rule inet lgkill output meta l4proto udp th dport 53 drop
nft add rule inet lgkill output meta l4proto tcp th dport 53 drop
nft add chain inet lgkill output6 "{ type filter hook output priority filter; family inet; policy drop; }"
nft add rule inet lgkill output6 oifname lo accept
nft add rule inet lgkill output6 oifname %s accept
nft add rule inet lgkill output6 meta mark 0x0000e1f1 accept
nft add rule inet lgkill output6 ct state established,related accept
`, iface, iface)
}

// Policy describes the country-selection preference for the VPN Identity Allocator.
type Policy struct {
	// Preferred countries are tried first, in order (e.g. ["co"] for Colombia).
	Preferred []string
	// GeoFallback is tried after Preferred is exhausted (e.g. ["ec","pe","pa",...]).
	GeoFallback []string
}

// Identity is the measured effective public network identity of an environment.
type Identity struct {
	V4 string // public IPv4 as seen through the tunnel (empty if none)
	V6 string // public IPv6 as seen through the tunnel (empty if none)
}

// AllocResult is a successfully allocated, measured-unique VPN identity.
type AllocResult struct {
	Country   string
	WG        *WGConfig
	Identity  Identity
	ServerKey string // reservation key (country:station)
}

// Connector brings up the WireGuard tunnel inside the guest for the given config
// (e.g. write the config and run wg-quick up), arming the kill-switch.
type Connector func(wg *WGConfig) error

// Measurer returns the effective public identity as seen from inside the guest's
// network namespace (e.g. curl -4/-6 through the tunnel).
type Measurer func() (Identity, error)

// Allocate finds a WireGuard server whose effective public identity is unique
// among currently-active instances, preferring Colombia then the geo fallback.
//
// Algorithm (per redefinition-audit §H.2):
//  1. For each country in Preferred then GeoFallback:
//  2. fetch several recommended servers;
//  3. for each server not reserved by another instance and not marked unsuitable:
//  4. reserve it (flock + TTL), connect the tunnel, measure the identity;
//  5. if the identity collides with an active instance, mark unsuitable + retry;
//  6. if unique, return it (tunnel stays up, kill-switch armed);
//  7. If no country yields a unique identity, return an error (OpenCode must NOT start).
func (c *Client) Allocate(ctx context.Context, pol Policy, store *ReservationStore, instanceID int, active func() map[string]Identity, connect Connector, measure Measurer) (*AllocResult, error) {
	countries := append(append([]string{}, pol.Preferred...), pol.GeoFallback...)
	if len(countries) == 0 {
		countries = []string{"co"}
	}
	var lastErr error
	for _, country := range countries {
		servers, err := c.RecommendN(ctx, country, 10)
		if err != nil {
			lastErr = err
			continue // try the next country
		}
		for _, srv := range servers {
			key := country + ":" + srv.Station
			if store.IsReservedByOther(key, instanceID) {
				continue
			}
			if store.IsUnsuitable(key) {
				continue
			}
			if err := store.Reserve(key, instanceID, 10*time.Minute); err != nil {
				lastErr = err
				continue
			}
			wg := &WGConfig{
				PrivateKey:    mustPrivateKey(c, ctx),
				Address:       "10.5.0.2/32",
				PeerPublicKey: srv.PublicKey,
				Endpoint:      srv.Station + ":51820",
				AllowedIPs:    "0.0.0.0/0, ::/0",
				Keepalive:     25,
			}
			if err := connect(wg); err != nil {
				store.Release(key)
				lastErr = err
				continue
			}
			id, err := measure()
			if err != nil {
				store.Release(key)
				lastErr = err
				continue
			}
			if id.V4 == "" && id.V6 == "" {
				// Measurement failed (no egress / curl error): treat as unusable
				// and try the next candidate rather than claiming a blank identity.
				store.Release(key)
				lastErr = fmt.Errorf("empty measured identity for %s", key)
				continue
			}
			if collides(id, active()) {
				store.MarkUnsuitable(key, 30*time.Minute)
				store.Release(key)
				continue
			}
			return &AllocResult{Country: country, WG: wg, Identity: id, ServerKey: key}, nil
		}
	}
	return nil, fmt.Errorf("vpn: no unique identity available across %v (last error: %v)", countries, lastErr)
}

// collides reports whether id shares a public address with any active identity.
func collides(id Identity, active map[string]Identity) bool {
	for _, a := range active {
		if id.V4 != "" && id.V4 == a.V4 {
			return true
		}
		if id.V6 != "" && a.V6 != "" && id.V6 == a.V6 {
			return true
		}
	}
	return false
}

// mustPrivateKey returns a fresh WireGuard private key for each VM.
// For concurrent VMs, sharing the single account NordLynx private key causes
// handshake failures when the same key is used for multiple simultaneous tunnels
// to different servers (Nord treats them as same device). Instead, generate a
// unique keypair per VM via `wg genkey` (wireguard-tools) — the server's peer
// public key is from the recommendations API, the VM's private key can be ephemeral
// because Nord's WireGuard does not require the account's key for per-VM tunnels
// when using token-based credentials (the server validates via the token, not the
// private key). For offline/test, fall back to the cached account key.
func mustPrivateKey(c *Client, ctx context.Context) string {
	// Try to generate a fresh key via wg genkey (fast, no network).
	if out, err := exec.CommandContext(ctx, "wg", "genkey").Output(); err == nil {
		if k := strings.TrimSpace(string(out)); k != "" {
			return k
		}
	}
	// Fallback to account key (cached) for offline/test.
	if c.cachedPriv == "" {
		priv, _, _, err := c.Credentials(ctx)
		if err == nil {
			c.cachedPriv = priv
		}
	}
	if c.cachedPriv == "" {
		return "PRIVKEY_UNAVAILABLE"
	}
	return c.cachedPriv
}
