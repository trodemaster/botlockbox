package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	"github.com/trodemaster/botlockbox/internal/secrets"
)

// makeEnclave creates a memguard enclave from a plaintext string and scrambles the source bytes.
func makeEnclave(val string) *memguard.Enclave {
	b := []byte(val)
	enc := memguard.NewEnclave(b)
	memguard.ScrambleBytes(b)
	return enc
}

// makeInjector constructs a minimal Injector with the given AllowedHosts and secret values.
func makeInjector(allowedHosts map[string][]string, secretVals map[string]string) *Injector {
	locked := make(map[string]*memguard.Enclave, len(secretVals))
	for k, v := range secretVals {
		locked[k] = makeEnclave(v)
	}
	return &Injector{
		envelope:      &secrets.SealedEnvelope{AllowedHosts: allowedHosts},
		lockedSecrets: locked,
	}
}

// makeResult constructs a UnsealResult with the given AllowedHosts and secret values.
func makeResult(allowedHosts map[string][]string, secretVals map[string]string) *secrets.UnsealResult {
	locked := make(map[string]*memguard.Enclave, len(secretVals))
	for k, v := range secretVals {
		locked[k] = makeEnclave(v)
	}
	return &secrets.UnsealResult{
		Envelope:      &secrets.SealedEnvelope{AllowedHosts: allowedHosts},
		LockedSecrets: locked,
	}
}

// readSecret reads a secret under RLock, mirroring what Handle() does.
func readSecret(inj *Injector, name string) (string, error) {
	inj.mu.RLock()
	defer inj.mu.RUnlock()
	return inj.getSecret(name)
}

// ---------------------------------------------------------------------------
// allowedHostsEqual
// ---------------------------------------------------------------------------

func TestAllowedHostsEqual(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		old     map[string][]string
		new     map[string][]string
		wantErr bool
	}{
		{
			name: "identical single secret",
			old:  map[string][]string{"tok": {"api.example.com"}},
			new:  map[string][]string{"tok": {"api.example.com"}},
		},
		{
			name: "identical multiple secrets",
			old:  map[string][]string{"tok": {"a.com", "b.com"}, "key": {"c.com"}},
			new:  map[string][]string{"tok": {"a.com", "b.com"}, "key": {"c.com"}},
		},
		{
			name: "host order differs — still equal",
			old:  map[string][]string{"tok": {"a.com", "b.com"}},
			new:  map[string][]string{"tok": {"b.com", "a.com"}},
		},
		{
			name: "both empty",
			old:  map[string][]string{},
			new:  map[string][]string{},
		},
		{
			name:    "extra key in new",
			old:     map[string][]string{"tok": {"a.com"}},
			new:     map[string][]string{"tok": {"a.com"}, "extra": {"b.com"}},
			wantErr: true,
		},
		{
			name:    "key missing from new",
			old:     map[string][]string{"tok": {"a.com"}, "key": {"b.com"}},
			new:     map[string][]string{"tok": {"a.com"}},
			wantErr: true,
		},
		{
			name:    "key renamed in new",
			old:     map[string][]string{"tok": {"a.com"}},
			new:     map[string][]string{"other": {"a.com"}},
			wantErr: true,
		},
		{
			name:    "host count increased",
			old:     map[string][]string{"tok": {"a.com"}},
			new:     map[string][]string{"tok": {"a.com", "b.com"}},
			wantErr: true,
		},
		{
			name:    "host count decreased",
			old:     map[string][]string{"tok": {"a.com", "b.com"}},
			new:     map[string][]string{"tok": {"a.com"}},
			wantErr: true,
		},
		{
			name:    "host value changed",
			old:     map[string][]string{"tok": {"a.com"}},
			new:     map[string][]string{"tok": {"z.com"}},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := allowedHostsEqual(tc.old, tc.new)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SwapSecrets — correctness
// ---------------------------------------------------------------------------

func TestSwapSecrets_HappyPath(t *testing.T) {
	t.Parallel()

	allowed := map[string][]string{"tok": {"api.example.com"}}
	inj := makeInjector(allowed, map[string]string{"tok": "old_value"})
	result := makeResult(allowed, map[string]string{"tok": "new_value"})

	if err := inj.SwapSecrets(result, allowed); err != nil {
		t.Fatalf("SwapSecrets returned unexpected error: %v", err)
	}

	got, err := inj.getSecret("tok")
	if err != nil {
		t.Fatalf("getSecret after swap: %v", err)
	}
	if got != "new_value" {
		t.Errorf("after swap: got %q, want %q", got, "new_value")
	}
}

func TestSwapSecrets_MultipleSecrets(t *testing.T) {
	t.Parallel()

	allowed := map[string][]string{
		"github": {"api.github.com"},
		"openai": {"api.openai.com"},
	}
	inj := makeInjector(allowed, map[string]string{"github": "ghp_old", "openai": "sk-old"})
	result := makeResult(allowed, map[string]string{"github": "ghp_new", "openai": "sk-new"})

	if err := inj.SwapSecrets(result, allowed); err != nil {
		t.Fatalf("SwapSecrets: %v", err)
	}

	for name, want := range map[string]string{"github": "ghp_new", "openai": "sk-new"} {
		got, err := inj.getSecret(name)
		if err != nil {
			t.Fatalf("getSecret(%q): %v", name, err)
		}
		if got != want {
			t.Errorf("getSecret(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestSwapSecrets_ValidationFailure_StateUnchanged(t *testing.T) {
	t.Parallel()

	allowed := map[string][]string{"tok": {"api.example.com"}}
	inj := makeInjector(allowed, map[string]string{"tok": "old_value"})

	// new envelope is missing "tok" from AllowedHosts — Validate() will reject it
	badResult := makeResult(map[string][]string{}, map[string]string{})

	if err := inj.SwapSecrets(badResult, allowed); err == nil {
		t.Fatal("expected error from Validate(), got nil")
	}

	// old secret must still be accessible
	got, err := inj.getSecret("tok")
	if err != nil {
		t.Fatalf("getSecret after rejected swap: %v", err)
	}
	if got != "old_value" {
		t.Errorf("after rejected swap: got %q, want %q", got, "old_value")
	}
}

func TestSwapSecrets_AllowedHostsChanged_StateUnchanged(t *testing.T) {
	t.Parallel()

	allowed := map[string][]string{"tok": {"api.example.com"}}
	inj := makeInjector(allowed, map[string]string{"tok": "old_value"})

	// new envelope passes Validate() but has a different AllowedHosts — re-seal required
	newAllowed := map[string][]string{"tok": {"api.example.com", "extra.example.com"}}
	result := makeResult(newAllowed, map[string]string{"tok": "new_value"})

	if err := inj.SwapSecrets(result, allowed); err == nil {
		t.Fatal("expected error when AllowedHosts changed, got nil")
	}

	got, err := inj.getSecret("tok")
	if err != nil {
		t.Fatalf("getSecret after rejected swap: %v", err)
	}
	if got != "old_value" {
		t.Errorf("after rejected swap: got %q, want %q", got, "old_value")
	}
}

func TestSwapSecrets_EnvelopePointerUpdated(t *testing.T) {
	t.Parallel()

	allowed := map[string][]string{"tok": {"api.example.com"}}
	inj := makeInjector(allowed, map[string]string{"tok": "old_value"})
	result := makeResult(allowed, map[string]string{"tok": "new_value"})
	newEnvelope := result.Envelope

	if err := inj.SwapSecrets(result, allowed); err != nil {
		t.Fatalf("SwapSecrets: %v", err)
	}

	if inj.envelope != newEnvelope {
		t.Error("envelope pointer was not updated after swap")
	}
}

// ---------------------------------------------------------------------------
// SwapSecrets — concurrency
// ---------------------------------------------------------------------------

// TestSwapSecrets_WaitsForReaders verifies that SwapSecrets acquires a write
// lock and waits for any in-flight readers to finish before swapping.
func TestSwapSecrets_WaitsForReaders(t *testing.T) {
	t.Parallel()

	allowed := map[string][]string{"tok": {"api.example.com"}}
	inj := makeInjector(allowed, map[string]string{"tok": "old_value"})
	result := makeResult(allowed, map[string]string{"tok": "new_value"})

	// Simulate an in-flight request holding the read lock.
	inj.mu.RLock()

	done := make(chan error, 1)
	go func() {
		done <- inj.SwapSecrets(result, allowed)
	}()

	// SwapSecrets must block while the read lock is held.
	select {
	case err := <-done:
		t.Fatalf("SwapSecrets completed before RLock was released (err=%v)", err)
	case <-time.After(50 * time.Millisecond):
		// expected: write lock is blocked by reader
	}

	inj.mu.RUnlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SwapSecrets returned unexpected error after unlock: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SwapSecrets did not complete after RLock was released")
	}

	got, err := inj.getSecret("tok")
	if err != nil {
		t.Fatalf("getSecret after swap: %v", err)
	}
	if got != "new_value" {
		t.Errorf("after swap: got %q, want %q", got, "new_value")
	}
}

// TestSwapSecrets_NoRace runs concurrent readers and writers to expose data
// races under the -race detector. It also validates that reads always return
// a consistent value (one of the known secret versions).
func TestSwapSecrets_NoRace(t *testing.T) {
	t.Parallel()

	allowed := map[string][]string{"tok": {"api.example.com"}}
	inj := makeInjector(allowed, map[string]string{"tok": "v0"})

	const (
		numReaders = 8
		readsEach  = 200
		numSwaps   = 10
	)

	// Build all swap results up-front so they don't race with the makeResult helper.
	results := make([]*secrets.UnsealResult, numSwaps)
	for i := range results {
		results[i] = makeResult(allowed, map[string]string{"tok": fmt.Sprintf("v%d", i+1)})
	}

	var wg sync.WaitGroup

	// Readers: repeatedly read the secret under RLock.
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < readsEach; j++ {
				val, err := readSecret(inj, "tok")
				if err != nil {
					t.Errorf("readSecret: %v", err)
					return
				}
				// Value must be one of the known versions — never garbled.
				if len(val) == 0 || val[0] != 'v' {
					t.Errorf("readSecret returned unexpected value %q", val)
				}
			}
		}()
	}

	// Writer: performs sequential swaps.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, result := range results {
			if err := inj.SwapSecrets(result, allowed); err != nil {
				t.Errorf("SwapSecrets: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}
