// Command baseline measures direct PKCS#11 signing throughput without a proxy.
//
// This is the "before" number the whole project is compared against, and it is written
// in Go on purpose. A baseline written in Rust would invite the objection that the
// comparison is really "badly written Rust versus well written Rust" rather than
// "naive architecture versus pooled architecture". Using a different language, a
// different PKCS#11 binding, and the most obvious possible code removes that objection.
//
// Three modes, because the interesting question is not just "how fast is one session"
// but "what happens when you do the obvious thing to make it faster":
//
//	serial          one session, one goroutine, sequential  -- the honest floor
//	naive-concurrent  N goroutines sharing one mutexed session -- the obvious mistake
//	pooled          N goroutines, N sessions                  -- what the proxy does
//
// The middle mode matters most. It shows that adding threads to a single session buys
// nothing, which is precisely the problem the proxy's worker pool exists to solve.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
)

type config struct {
	module     string
	tokenLabel string
	pin        string
	keyLabel   string
	mechanism  string
	mode       string
	workers    int
	duration   time.Duration
	warmup     time.Duration
	jsonOut    string
}

// result is one measurement, shaped to sit alongside the Rust harness output.
type result struct {
	Mode        string  `json:"mode"`
	Mechanism   string  `json:"mechanism"`
	KeyLabel    string  `json:"key_label"`
	Workers     int     `json:"workers"`
	Operations  int64   `json:"operations"`
	DurationSec float64 `json:"duration_sec"`
	OpsPerSec   float64 `json:"ops_per_sec"`
	P50Micros   float64 `json:"p50_micros"`
	P99Micros   float64 `json:"p99_micros"`
	MaxMicros   float64 `json:"max_micros"`
	Host        hostInfo `json:"host"`
}

type hostInfo struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	NumCPU  int    `json:"num_cpu"`
	GoVer   string `json:"go_version"`
	Module  string `json:"pkcs11_module"`
	Stamped string `json:"timestamp_utc"`
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.module, "module", envOr("PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"), "PKCS#11 module path")
	flag.StringVar(&cfg.tokenLabel, "token", envOr("TOKEN_LABEL", "grpc-low-latency"), "token label")
	flag.StringVar(&cfg.pin, "pin", os.Getenv("USER_PIN"), "user PIN")
	flag.StringVar(&cfg.keyLabel, "key", "demo-ec-p256", "key label")
	flag.StringVar(&cfg.mechanism, "mechanism", "ecdsa", "ecdsa or rsa")
	flag.StringVar(&cfg.mode, "mode", "serial", "serial, naive-concurrent, or pooled")
	flag.IntVar(&cfg.workers, "workers", runtime.NumCPU(), "goroutines for concurrent modes")
	flag.DurationVar(&cfg.duration, "duration", 5*time.Second, "measurement window")
	flag.DurationVar(&cfg.warmup, "warmup", 500*time.Millisecond, "discarded warm-up")
	flag.StringVar(&cfg.jsonOut, "json", "", "write the result as JSON to this path")
	flag.Parse()

	if cfg.pin == "" {
		fatal(fmt.Errorf("USER_PIN is not set; refusing to guess a PIN"))
	}

	res, err := run(cfg)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("\n-- %s, %s, %s --\n", res.Mode, res.Mechanism, res.KeyLabel)
	fmt.Printf("%-14s %d\n", "workers", res.Workers)
	fmt.Printf("%-14s %d\n", "operations", res.Operations)
	fmt.Printf("%-14s %.2fs\n", "duration", res.DurationSec)
	fmt.Printf("%-14s %.0f ops/sec\n", "throughput", res.OpsPerSec)
	fmt.Printf("%-14s %.1f us\n", "p50", res.P50Micros)
	fmt.Printf("%-14s %.1f us\n", "p99", res.P99Micros)
	fmt.Printf("%-14s %.1f us\n", "max", res.MaxMicros)

	if cfg.jsonOut != "" {
		blob, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(cfg.jsonOut, append(blob, '\n'), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("\nsaved: %s\n", cfg.jsonOut)
	}
}

func run(cfg config) (result, error) {
	ctx := pkcs11.New(cfg.module)
	if ctx == nil {
		return result{}, fmt.Errorf("failed to load PKCS#11 module %q", cfg.module)
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		return result{}, fmt.Errorf("C_Initialize: %w", err)
	}
	defer ctx.Finalize()

	slot, err := findSlot(ctx, cfg.tokenLabel)
	if err != nil {
		return result{}, err
	}

	switch cfg.mode {
	case "serial":
		return measure(ctx, slot, cfg, 1, true)
	case "naive-concurrent":
		return measure(ctx, slot, cfg, cfg.workers, true)
	case "pooled":
		return measure(ctx, slot, cfg, cfg.workers, false)
	default:
		return result{}, fmt.Errorf("unknown mode %q", cfg.mode)
	}
}

// measure runs the load. When shared is true every goroutine contends for one session
// behind a mutex; otherwise each opens its own.
func measure(ctx *pkcs11.Ctx, slot uint, cfg config, workers int, shared bool) (result, error) {
	mech, digest, err := mechanismFor(cfg.mechanism)
	if err != nil {
		return result{}, err
	}

	type worker struct {
		session pkcs11.SessionHandle
		key     pkcs11.ObjectHandle
	}

	var sharedMu sync.Mutex
	sessions := make([]worker, 0, workers)

	// A shared session is opened once and reused; separate sessions are opened per
	// goroutine. Either way the object handle is found before measurement starts, so
	// C_FindObjects never appears in the timed loop.
	n := workers
	if shared {
		n = 1
	}
	for i := 0; i < n; i++ {
		sh, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return result{}, fmt.Errorf("C_OpenSession: %w", err)
		}
		defer ctx.CloseSession(sh)

		if err := ctx.Login(sh, pkcs11.CKU_USER, cfg.pin); err != nil {
			// Login state is per-token for the application, so later sessions find
			// themselves already logged in. That is success, not an error.
			if !strings.Contains(err.Error(), "CKR_USER_ALREADY_LOGGED_IN") {
				return result{}, fmt.Errorf("C_Login: %w", err)
			}
		}

		key, err := findKey(ctx, sh, cfg.keyLabel)
		if err != nil {
			return result{}, err
		}
		sessions = append(sessions, worker{session: sh, key: key})
	}

	sign := func(w worker) error {
		if err := ctx.SignInit(w.session, mech, w.key); err != nil {
			return err
		}
		_, err := ctx.Sign(w.session, digest)
		return err
	}

	// Warm up so lazy initialization inside the module is not measured.
	deadline := time.Now().Add(cfg.warmup)
	for time.Now().Before(deadline) {
		if err := sign(sessions[0]); err != nil {
			return result{}, fmt.Errorf("warm-up sign: %w", err)
		}
	}

	var (
		wg       sync.WaitGroup
		latMu    sync.Mutex
		latency  []time.Duration
		opsTotal int64
		start    = make(chan struct{})
	)

	for i := 0; i < workers; i++ {
		w := sessions[0]
		if !shared {
			w = sessions[i]
		}

		wg.Add(1)
		go func(w worker) {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			var ops int64

			<-start
			stop := time.Now().Add(cfg.duration)
			for time.Now().Before(stop) {
				t0 := time.Now()
				var err error
				if shared {
					// The naive mistake, made explicit: one session serialized behind a
					// mutex, so added goroutines wait rather than work.
					sharedMu.Lock()
					err = sign(w)
					sharedMu.Unlock()
				} else {
					err = sign(w)
				}
				if err != nil {
					return
				}
				local = append(local, time.Since(t0))
				ops++
			}

			latMu.Lock()
			latency = append(latency, local...)
			opsTotal += ops
			latMu.Unlock()
		}(w)
	}

	t0 := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(t0)

	if len(latency) == 0 {
		return result{}, fmt.Errorf("no operations completed")
	}
	sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })

	pct := func(p float64) float64 {
		idx := int(float64(len(latency)) * p / 100)
		if idx >= len(latency) {
			idx = len(latency) - 1
		}
		return float64(latency[idx].Microseconds())
	}

	return result{
		Mode:        cfg.mode,
		Mechanism:   cfg.mechanism,
		KeyLabel:    cfg.keyLabel,
		Workers:     workers,
		Operations:  opsTotal,
		DurationSec: elapsed.Seconds(),
		OpsPerSec:   float64(opsTotal) / elapsed.Seconds(),
		P50Micros:   pct(50),
		P99Micros:   pct(99),
		MaxMicros:   float64(latency[len(latency)-1].Microseconds()),
		Host: hostInfo{
			OS: runtime.GOOS, Arch: runtime.GOARCH, NumCPU: runtime.NumCPU(),
			GoVer: runtime.Version(), Module: cfg.module,
			Stamped: time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// mechanismFor returns the signing mechanism and the payload to sign.
//
// CKM_ECDSA signs a bare digest; CKM_SHA256_RSA_PKCS hashes the message itself. Both
// match what the Rust proxy does, so the comparison is like for like.
func mechanismFor(name string) ([]*pkcs11.Mechanism, []byte, error) {
	message := []byte("baseline benchmark payload")
	switch name {
	case "ecdsa":
		digest := sha256.Sum256(message)
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, digest[:], nil
	case "rsa":
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, message, nil
	default:
		return nil, nil, fmt.Errorf("unknown mechanism %q (want ecdsa or rsa)", name)
	}
}

func findSlot(ctx *pkcs11.Ctx, label string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("C_GetSlotList: %w", err)
	}
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimSpace(info.Label) == label {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("no slot holds a token labelled %q", label)
}

func findKey(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(sh, template); err != nil {
		return 0, fmt.Errorf("C_FindObjectsInit: %w", err)
	}
	objs, _, err := ctx.FindObjects(sh, 1)
	if err != nil {
		return 0, fmt.Errorf("C_FindObjects: %w", err)
	}
	if err := ctx.FindObjectsFinal(sh); err != nil {
		return 0, fmt.Errorf("C_FindObjectsFinal: %w", err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("no private key labelled %q", label)
	}
	return objs[0], nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "baseline: %v\n", err)
	os.Exit(1)
}

