package vpn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConfigString(t *testing.T) {
	wg := &WGConfig{
		PrivateKey:    "priv",
		Address:       "10.5.0.2/32",
		PeerPublicKey: "pub",
		Endpoint:      "1.2.3.4:51820",
		AllowedIPs:    "0.0.0.0/0, ::/0",
		Keepalive:     25,
	}
	s := ConfigString(wg)
	for _, want := range []string{"[Interface]", "PrivateKey = priv", "Address = 10.5.0.2/32", "[Peer]", "PublicKey = pub", "Endpoint = 1.2.3.4:51820", "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25"} {
		if !strings.Contains(s, want) {
			t.Fatalf("config missing %q:\n%s", want, s)
		}
	}
}

func TestKillSwitchScript(t *testing.T) {
	s := KillSwitchScript("lgwg0")
	for _, want := range []string{"inet lgkill", "policy drop", "oifname lgwg0 accept", "ct mark 0x0000e1f1 accept"} {
		if !strings.Contains(s, want) {
			t.Fatalf("killswitch missing %q:\n%s", want, s)
		}
	}
}

// TestGenerate uses a mocked NordVPN API to validate the request/parse path.
func TestGenerate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/services/credentials", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic dG9rZW46dG9r" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"nordlynx_private_key":"priv","username":"u","password":"p"}`))
	})
	mux.HandleFunc("/v1/servers/countries", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"id":1,"code":"de","name":"Germany"},{"id":2,"code":"us","name":"United States"}]`))
	})
	mux.HandleFunc("/v1/servers/recommendations", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "filters%5Bcountry_id%5D=1") {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		w.Write([]byte(`[{"station":"5.6.7.8","technologies":[{"identifier":"wireguard_udp","metadata":"serverpub"}]}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{Token: "tok", HTTP: srv.Client(), BaseURL: srv.URL}
	wg, err := c.Generate(context.Background(), "de")
	if err != nil {
		t.Fatal(err)
	}
	if wg.PrivateKey != "priv" || wg.PeerPublicKey != "serverpub" {
		t.Fatalf("unexpected wg: %+v", wg)
	}
	if wg.Endpoint != "5.6.7.8:51820" {
		t.Fatalf("endpoint=%q", wg.Endpoint)
	}
}

// mockServer builds a Client whose Nord API is served by mux. Recommendations are
// derived from the station->pub map per country (country code -> list of stations).
func mockClient(t *testing.T, stations map[string][]string) (*Client, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/services/credentials", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic dG9rZW46dG9r" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"nordlynx_private_key":"privKEY","username":"u","password":"p"}`))
	})
	mux.HandleFunc("/v1/servers/countries", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"id":1,"code":"co","name":"Colombia"},{"id":2,"code":"ec","name":"Ecuador"},{"id":3,"code":"us","name":"United States"}]`))
	})
	mux.HandleFunc("/v1/servers/recommendations", func(w http.ResponseWriter, r *http.Request) {
		// country_id is the only field we key on.
		q := r.URL.Query().Get("filters[country_id]")
		var code string
		switch q {
		case "1":
			code = "co"
		case "2":
			code = "ec"
		case "3":
			code = "us"
		}
		var recs []map[string]any
		for _, st := range stations[code] {
			recs = append(recs, map[string]any{
				"station": st,
				"technologies": []map[string]any{
					{"identifier": "wireguard_udp", "metadata": "pub_" + st},
				},
			})
		}
		b, _ := json.Marshal(recs)
		w.Write(b)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{Token: "tok", HTTP: srv.Client(), BaseURL: srv.URL}, srv
}

func TestAllocateColombiaPreferred(t *testing.T) {
	// co has two servers; co1 collides with an active identity, co2 is unique.
	// ec also has a unique server, but Colombia must win.
	c, _ := mockClient(t, map[string][]string{"co": {"co1", "co2"}, "ec": {"ec1"}})
	store := NewReservationStore(t.TempDir() + "/res.json")
	active := map[string]Identity{"other": {V4: "1.1.1.1"}}

	var mu sync.Mutex
	var last string
	connect := func(wg *WGConfig) error {
		mu.Lock()
		last = wg.Endpoint
		mu.Unlock()
		return nil
	}
	measure := func() (Identity, error) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(last, "co1"):
			return Identity{V4: "1.1.1.1"}, nil // collides
		case strings.Contains(last, "co2"):
			return Identity{V4: "2.2.2.2"}, nil // unique
		case strings.Contains(last, "ec1"):
			return Identity{V4: "3.3.3.3"}, nil
		}
		return Identity{V4: "9.9.9.9"}, nil
	}

	res, err := c.Allocate(context.Background(), Policy{Preferred: []string{"co"}, GeoFallback: []string{"ec"}},
		store, 1, func() map[string]Identity { return active }, connect, measure)
	if err != nil {
		t.Fatal(err)
	}
	if res.Country != "co" {
		t.Fatalf("expected Colombia preferred, got %q", res.Country)
	}
	if res.Identity.V4 != "2.2.2.2" {
		t.Fatalf("expected unique co2 identity, got %q", res.Identity.V4)
	}
}

func TestAllocateFallbackWhenColombiaExhausted(t *testing.T) {
	// All Colombian servers collide; Ecuador has a unique one.
	c, _ := mockClient(t, map[string][]string{"co": {"co1", "co2"}, "ec": {"ec1"}})
	store := NewReservationStore(t.TempDir() + "/res.json")
	active := map[string]Identity{"other": {V4: "1.1.1.1"}}

	var mu sync.Mutex
	var last string
	connect := func(wg *WGConfig) error {
		mu.Lock()
		last = wg.Endpoint
		mu.Unlock()
		return nil
	}
	measure := func() (Identity, error) {
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(last, "co") {
			return Identity{V4: "1.1.1.1"}, nil // always collide for co
		}
		return Identity{V4: "3.3.3.3"}, nil // ec unique
	}
	res, err := c.Allocate(context.Background(), Policy{Preferred: []string{"co"}, GeoFallback: []string{"ec"}},
		store, 1, func() map[string]Identity { return active }, connect, measure)
	if err != nil {
		t.Fatal(err)
	}
	if res.Country != "ec" {
		t.Fatalf("expected fallback to Ecuador, got %q", res.Country)
	}
}

func TestAllocateNoUnique(t *testing.T) {
	// Every server collides -> error, OpenCode must not start.
	c, _ := mockClient(t, map[string][]string{"co": {"co1"}, "ec": {"ec1"}})
	store := NewReservationStore(t.TempDir() + "/res.json")
	active := map[string]Identity{"a": {V4: "1.1.1.1"}, "b": {V4: "3.3.3.3"}}

	connect := func(wg *WGConfig) error { return nil }
	measure := func() (Identity, error) { return Identity{V4: "1.1.1.1"}, nil }
	_, err := c.Allocate(context.Background(), Policy{Preferred: []string{"co"}, GeoFallback: []string{"ec"}},
		store, 1, func() map[string]Identity { return active }, connect, measure)
	if err == nil {
		t.Fatal("expected error when no unique identity available")
	}
}

// forbidNordvpnRunCmd replaces runCmd with a spy that records every invocation
// and fails the test if anything ever runs the `nordvpn` CLI. It returns canned
// `wg showconf nordlynx` output so host-key harvest (the legitimate, read-only
// wg call) keeps working.
func forbidNordvpnRunCmd(t *testing.T) (restore func(), got *[][]string) {
	t.Helper()
	saved := runCmd
	invocations := [][]string{}
	canned := "[Interface]\nPrivateKey = HOSTPRIVKEY0123456789abcdef\nAddress = 10.5.0.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = hostpeerpub\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
	runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		full := append([]string{name}, args...)
		invocations = append(invocations, full)
		if name == "nordvpn" {
			t.Errorf("REGRESSION: host-VPN mutation via `nordvpn %v`", args)
		}
		for _, a := range args {
			if a == "connect" || a == "disconnect" {
				t.Errorf("REGRESSION: `nordvpn %s` would mutate the host VPN", a)
			}
		}
		return []byte(canned), nil
	}
	return func() { runCmd = saved }, &invocations
}

// TestGenerateSafeNoHostMutation covers BOTH code paths of GenerateSafe
// (token API and host-key harvest fallback) and asserts the host VPN is never
// touched by `nordvpn connect`/`disconnect` in either case.
func TestGenerateSafeNoHostMutation(t *testing.T) {
	restore, inv := forbidNordvpnRunCmd(t)
	defer restore()

	// Token path (preferred): client with a token hits the mock Nord API.
	c, _ := mockClient(t, map[string][]string{"co": {"co1"}})
	wg, err := GenerateSafe(context.Background(), c, "co")
	if err != nil {
		t.Fatal(err)
	}
	if wg == nil || wg.PeerPublicKey == "" || wg.Endpoint == "" {
		t.Fatalf("token-path config incomplete: %+v", wg)
	}

	// Host-key harvest fallback: nil client must not invoke `nordvpn` either.
	wg2, err := GenerateSafe(context.Background(), nil, "co")
	if err == nil && (wg2 == nil || wg2.PeerPublicKey == "") {
		t.Fatalf("host-key fallback produced incomplete config: %+v (err=%v)", wg2, err)
	}
	// The only acceptable external command is `wg showconf nordlynx`
	// (read-only harvest); anything `nordvpn` is a hard failure.
	for _, call := range *inv {
		if call[0] != "wg" {
			t.Errorf("unexpected external command during config generation: %v", call)
		}
	}
}

// TestGenerateFromHostKeyUsesHostKey verifies the harvest path derives the
// private key + address from the host's read-only `wg showconf nordlynx` output
// and pairs it with a recommended server, without touching `nordvpn`.
func TestGenerateFromHostKeyUsesHostKey(t *testing.T) {
	restore, _ := forbidNordvpnRunCmd(t)
	defer restore()

	c, _ := mockClient(t, map[string][]string{"co": {"co1"}})
	wg, err := GenerateFromHostKey(context.Background(), c, "co")
	if err != nil {
		t.Fatal(err)
	}
	if wg.PrivateKey != "HOSTPRIVKEY0123456789abcdef" {
		t.Fatalf("expected host private key, got %q", wg.PrivateKey)
	}
	if wg.Address != "10.5.0.2/32" {
		t.Fatalf("expected host address, got %q", wg.Address)
	}
	if wg.PeerPublicKey != "pub_co1" {
		t.Fatalf("expected recommended server pubkey, got %q", wg.PeerPublicKey)
	}
	if wg.Endpoint != "co1:51820" {
		t.Fatalf("expected recommended endpoint, got %q", wg.Endpoint)
	}
}

// TestGenerateForServerTokenPath verifies the per-server generator uses the Nord
// API keypair (never the host VPN) when a token is configured.
func TestGenerateForServerTokenPath(t *testing.T) {
	restore, _ := forbidNordvpnRunCmd(t)
	defer restore()
	c, _ := mockClient(t, map[string][]string{"co": {"co1"}})
	wg, err := GenerateForServer(context.Background(), c, "co", ServerSuggestion{Station: "co1", PublicKey: "pub_co1"})
	if err != nil {
		t.Fatal(err)
	}
	if wg.PrivateKey != "privKEY" {
		t.Fatalf("token path should use API keypair, got %q", wg.PrivateKey)
	}
	if wg.PeerPublicKey != "pub_co1" {
		t.Fatalf("unexpected peer pubkey %q", wg.PeerPublicKey)
	}
	if wg.Endpoint != "co1:51820" {
		t.Fatalf("unexpected endpoint %q", wg.Endpoint)
	}
}

// TestGenerateForServerHostKeyFallback verifies the no-token fallback derives the
// private key + address from the host's READ-ONLY `wg showconf nordlynx` and never
// invokes the `nordvpn` CLI.
func TestGenerateForServerHostKeyFallback(t *testing.T) {
	restore, _ := forbidNordvpnRunCmd(t)
	defer restore()
	wg, err := GenerateForServer(context.Background(), nil, "co", ServerSuggestion{Station: "co1", PublicKey: "pub_co1"})
	if err != nil {
		t.Fatal(err)
	}
	if wg.PrivateKey != "HOSTPRIVKEY0123456789abcdef" {
		t.Fatalf("host-key fallback expected host key, got %q", wg.PrivateKey)
	}
	if wg.Address != "10.5.0.2/32" {
		t.Fatalf("unexpected address %q", wg.Address)
	}
	if wg.Endpoint != "co1:51820" {
		t.Fatalf("unexpected endpoint %q", wg.Endpoint)
	}
}

func TestReservationStoreExcludesOther(t *testing.T) {
	store := NewReservationStore(t.TempDir() + "/res.json")
	if err := store.Reserve("co:co1", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !store.IsReservedByOther("co:co1", 2) {
		t.Fatal("should report reserved by other")
	}
	if store.IsReservedByOther("co:co1", 1) {
		t.Fatal("should NOT report reserved by self")
	}
	if err := store.MarkUnsuitable("co:co2", time.Minute); err != nil {
		t.Fatal(err)
	}
	if !store.IsUnsuitable("co:co2") {
		t.Fatal("should be unsuitable")
	}
	if err := store.Release("co:co1"); err != nil {
		t.Fatal(err)
	}
	if store.IsReservedByOther("co:co1", 2) {
		t.Fatal("after release should not be reserved")
	}
}
