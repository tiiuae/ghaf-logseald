// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tiiuae/ghaf-logseald/internal/journal"
	"github.com/tiiuae/ghaf-logseald/internal/producer"
	"github.com/tiiuae/ghaf-logseald/internal/protocol"
	"github.com/tiiuae/ghaf-logseald/internal/sealer"
	"github.com/tiiuae/ghaf-logseald/internal/store"
	"github.com/tiiuae/ghaf-logseald/internal/tlsutil"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lmsgprefix)
	log.SetPrefix("logseald: ")
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "producer":
		err = runProducer(ctx, os.Args[2:])
	case "sealer":
		err = runSealer(ctx, os.Args[2:])
	case "verify-producer":
		err = verifyProducer(os.Args[2:])
	case "verify-sealer":
		err = verifySealer(os.Args[2:])
	default:
		usage()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		if errors.Is(err, store.ErrCapacity) {
			log.Print(err)
			os.Exit(75)
		}
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: logseald <producer|sealer|verify-producer|verify-sealer> [options]")
	os.Exit(2)
}

type producerOptions struct {
	resetOnCredentialChange                                                                       bool
	stateDir, sourceName, endpoint, certFile, keyFile, caFile, serverName, timePolicy, journalctl string
	blockRecords, maxPending                                                                      int
	blockInterval, retryInterval, requestTimeout                                                  time.Duration
	revokedKeys                                                                                   string
	limits                                                                                        store.Limits
}

func storageFlags(flags *flag.FlagSet, limits *store.Limits) {
	flags.Int64Var(&limits.Bytes, "max-state-bytes", limits.Bytes, "maximum evidence file bytes, including pending blocks")
	flags.IntVar(&limits.Entries, "max-state-entries", limits.Entries, "maximum evidence entries")
}

func runProducer(ctx context.Context, args []string) error {
	hostname, _ := os.Hostname()
	options := producerOptions{}
	flags := flag.NewFlagSet("producer", flag.ContinueOnError)
	options.limits = store.ProducerLimits()
	flags.BoolVar(&options.resetOnCredentialChange, "reset-on-credential-change", false, "discard prior sealing state when the producer key or CA bundle changes; initializes legacy state once")
	storageFlags(flags, &options.limits)
	flags.IntVar(&options.limits.WindowEntries, "window-entries", 20000, "maximum retained sealed blocks; zero disables expiry")
	flags.StringVar(&options.revokedKeys, "revoked-peer-keys", "", "file of denied peer SPKI IDs; restart after updates")
	flags.StringVar(&options.stateDir, "state-dir", "/var/lib/logseald/producer", "durable producer state directory")
	flags.StringVar(&options.sourceName, "source", hostname, "source name stored in blocks")
	flags.StringVar(&options.endpoint, "sealer-url", "https://admin-vm:59631/v1/seal", "sealer HTTPS endpoint")
	flags.StringVar(&options.certFile, "cert", "", "producer client certificate")
	flags.StringVar(&options.keyFile, "key", "", "producer client private key")
	flags.StringVar(&options.caFile, "ca", "", "trusted CA bundle")
	flags.StringVar(&options.serverName, "server-name", "admin-vm", "expected sealer certificate DNS name")
	flags.StringVar(&options.timePolicy, "tls-time-policy", string(tlsutil.StaticCert), "wall-clock or static-cert")
	flags.StringVar(&options.journalctl, "journalctl", "journalctl", "journalctl executable")
	flags.IntVar(&options.blockRecords, "block-records", 256, "maximum records per block")
	flags.IntVar(&options.maxPending, "max-pending-blocks", 64, "maximum durable offline queue depth")
	flags.DurationVar(&options.blockInterval, "block-interval", 5*time.Second, "maximum in-memory block age")
	flags.DurationVar(&options.retryInterval, "retry-interval", 2*time.Second, "sealer retry interval")
	flags.DurationVar(&options.requestTimeout, "request-timeout", 10*time.Second, "HTTPS request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if options.certFile == "" || options.keyFile == "" || options.caFile == "" || options.sourceName == "" || options.serverName == "" {
		return fmt.Errorf("--cert, --key, --ca, --source and --server-name are required")
	}
	if options.blockInterval <= 0 || options.retryInterval <= 0 || options.requestTimeout <= 0 {
		return fmt.Errorf("block, retry and request timeouts must be positive")
	}
	endpoint, err := url.ParseRequestURI(options.endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return fmt.Errorf("--sealer-url must be an absolute HTTPS URL")
	}
	policy, err := tlsutil.ParseTimePolicy(options.timePolicy)
	if err != nil {
		return err
	}
	leaf, err := tlsutil.LoadLeaf(options.certFile)
	if err != nil {
		return err
	}
	tlsConfig, err := tlsutil.ClientConfig(options.certFile, options.keyFile, options.caFile, options.serverName, policy, options.revokedKeys)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(options.stateDir, 0o750); err != nil {
		return err
	}
	unlock, err := store.Lock(options.stateDir, true)
	if err != nil {
		return err
	}
	defer unlock()
	if options.resetOnCredentialChange {
		if err := prepareCredentialEpoch(options.stateDir, "producer", options.caFile, leaf); err != nil {
			return err
		}
	}
	engine, err := producer.Open(options.stateDir, tlsutil.ChainID(leaf), options.sourceName, options.blockRecords, options.maxPending, options.limits)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: options.requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	commandArgs := []string{"--output=export", "--follow", "--all", "--no-pager"}
	if engine.LastCursor() != "" {
		commandArgs = append(commandArgs, "--after-cursor="+engine.LastCursor())
	}
	command := exec.CommandContext(ctx, options.journalctl, commandArgs...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open journalctl output: %w", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}
	defer stopJournal(command)

	records := make(chan protocol.Record, 1)
	readErrors := make(chan error, 1)
	go readJournal(stdout, records, readErrors)
	flushTicker := time.NewTicker(options.blockInterval)
	defer flushTicker.Stop()
	retryTicker := time.NewTicker(options.retryInterval)
	defer retryTicker.Stop()
	immediateRetry := make(chan time.Time, 1)
	immediateRetry <- time.Now()
	submission := submissionState{}

	for {
		var readable <-chan protocol.Record
		if engine.CanRead() {
			readable = records
		}
		select {
		case <-ctx.Done():
			if engine.HasBatch() {
				if err := engine.Flush(); err != nil {
					return fmt.Errorf("flush block during shutdown: %w", err)
				}
			}
			return ctx.Err()
		case err := <-readErrors:
			return fmt.Errorf("journal stream ended: %w", err)
		case record := <-readable:
			if err := engine.Append(record); err != nil {
				return fmt.Errorf("append journal record: %w", err)
			}
		case <-flushTicker.C:
			if engine.HasBatch() && engine.CanRead() {
				if err := engine.Flush(); err != nil {
					return fmt.Errorf("flush journal block: %w", err)
				}
			}
		case <-retryTicker.C:
			submission.submitOne(ctx, engine, client, options.endpoint)
		case <-immediateRetry:
			submission.submitOne(ctx, engine, client, options.endpoint)
		}
	}
}

func stopJournal(command *exec.Cmd) {
	// A parser failure does not stop journalctl --follow; kill before waiting.
	_ = command.Process.Kill()
	_ = command.Wait()
}

func readJournal(input io.Reader, records chan<- protocol.Record, errors chan<- error) {
	reader := journal.NewReader(input)
	for {
		record, err := reader.ReadRecord()
		if err != nil {
			errors <- err
			return
		}
		records <- record
	}
}

type submissionState struct {
	failing bool
}

func (state *submissionState) submitOne(ctx context.Context, engine *producer.Engine, client *http.Client, endpoint string) {
	submitted, err := engine.SubmitOne(ctx, client, endpoint)
	// Log only state transitions to avoid an unbounded journal/sealing feedback loop.
	if err != nil {
		if !state.failing {
			log.Printf("seal submission unavailable; queueing locally (queue depth %d): %v", engine.QueueDepth(), err)
		}
		state.failing = true
	} else if submitted && state.failing {
		log.Printf("seal submission recovered (queue depth %d)", engine.QueueDepth())
		state.failing = false
	}
}

func runSealer(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sealer", flag.ContinueOnError)
	var resetOnCredentialChange bool
	flags.BoolVar(&resetOnCredentialChange, "reset-on-credential-change", false, "discard prior sealing state when the CA bundle changes; initializes legacy state once")
	limits := store.SealerLimits()
	storageFlags(flags, &limits)
	flags.BoolVar(&limits.Compact, "compact-state", true, "retain signed chain heads instead of full blocks")
	flags.Int64Var(&limits.ChainBytes, "max-chain-bytes", limits.ChainBytes, "maximum ledger bytes per producer")
	flags.IntVar(&limits.ChainEntries, "max-chain-entries", limits.ChainEntries, "maximum ledger entries per producer")
	var revokedKeys string
	flags.StringVar(&revokedKeys, "revoked-peer-keys", "", "file of denied peer SPKI IDs; restart after updates")
	var stateDir, listenAddress, certFile, keyFile, caFile, timePolicy string
	flags.StringVar(&stateDir, "state-dir", "/var/lib/logseald/sealer", "durable sealer state directory")
	flags.StringVar(&listenAddress, "listen", "0.0.0.0:59631", "HTTPS listen address")
	flags.StringVar(&certFile, "cert", "", "sealer server certificate")
	flags.StringVar(&keyFile, "key", "", "sealer server private key")
	flags.StringVar(&caFile, "ca", "", "trusted producer CA bundle")
	flags.StringVar(&timePolicy, "tls-time-policy", string(tlsutil.StaticCert), "wall-clock or static-cert")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if certFile == "" || keyFile == "" || caFile == "" {
		return fmt.Errorf("--cert, --key and --ca are required")
	}
	policy, err := tlsutil.ParseTimePolicy(timePolicy)
	if err != nil {
		return err
	}
	tlsConfig, err := tlsutil.ServerConfig(certFile, keyFile, caFile, policy, revokedKeys)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	unlock, err := store.Lock(stateDir, true)
	if err != nil {
		return err
	}
	defer unlock()
	if resetOnCredentialChange {
		if err := prepareCredentialEpoch(stateDir, "sealer", caFile, nil); err != nil {
			return err
		}
	}
	state, err := store.OpenSealer(stateDir, limits)
	if err != nil {
		return err
	}
	transportIdentity, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load GIVC key pair for signing-key binding: %w", err)
	}
	transportCertificate, err := tlsutil.LeafFromTLSCertificate(transportIdentity)
	if err != nil {
		return err
	}
	transportSigner, ok := transportIdentity.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("GIVC private key cannot sign a key binding")
	}
	keyBinding, err := protocol.NewKeyBinding(transportCertificate, transportSigner, state.PublicKey())
	if err != nil {
		return fmt.Errorf("bind sealer key to GIVC identity: %w", err)
	}
	keyBindingHeader, err := protocol.EncodeKeyBindingHeader(keyBinding)
	if err != nil {
		return err
	}
	listener, err := openListener(listenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	server := &http.Server{
		Handler:           sealer.NewHandler(state, keyBindingHeader),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	log.Printf("sealer listening on %s with %s TLS time policy", listenAddress, policy)
	err = server.Serve(tls.NewListener(listener, tlsConfig))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func openListener(address string) (net.Listener, error) {
	if !strings.HasPrefix(address, "unix:") {
		return net.Listen("tcp", address)
	}
	path := strings.TrimPrefix(address, "unix:")
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("Unix listener path must be absolute")
	}
	if _, err := os.Lstat(path); err == nil {
		connection, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("Unix listener is already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("validate existing Unix listener: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale Unix listener: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Unix listener: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("protect Unix listener: %w", err)
	}
	return listener, nil
}

func verifyProducer(args []string) error {
	hostname, _ := os.Hostname()
	flags := flag.NewFlagSet("verify-producer", flag.ContinueOnError)
	limits := store.ProducerLimits()
	storageFlags(flags, &limits)
	var stateDir, certFile, sourceName string
	flags.StringVar(&stateDir, "state-dir", "/var/lib/logseald/producer", "producer state directory")
	flags.StringVar(&certFile, "cert", "", "producer certificate")
	flags.StringVar(&sourceName, "source", hostname, "expected source name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if certFile == "" || sourceName == "" {
		return fmt.Errorf("--cert and --source are required")
	}
	leaf, err := tlsutil.LoadLeaf(certFile)
	if err != nil {
		return err
	}
	state, err := store.ReadProducer(stateDir, tlsutil.ChainID(leaf), sourceName, limits)
	if err != nil {
		return err
	}
	fmt.Printf("PASS: retained producer history is valid: %d sealed total, %d retained sealed, %d queued blocks, %d expired blocks, cursor %q\n", state.TotalSealed(), state.SealedCount(), state.QueueDepth(), state.ExpiredCount(), state.LastCursor())
	return nil
}

func verifySealer(args []string) error {
	flags := flag.NewFlagSet("verify-sealer", flag.ContinueOnError)
	limits := store.SealerLimits()
	storageFlags(flags, &limits)
	flags.Int64Var(&limits.ChainBytes, "max-chain-bytes", limits.ChainBytes, "maximum ledger bytes per producer")
	flags.IntVar(&limits.ChainEntries, "max-chain-entries", limits.ChainEntries, "maximum ledger entries per producer")
	var stateDir string
	flags.StringVar(&stateDir, "state-dir", "/var/lib/logseald/sealer", "sealer state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(stateDir, "sealer.key")); err != nil {
		return fmt.Errorf("sealer key is unavailable: %w", err)
	}
	state, err := store.ReadSealer(stateDir, limits)
	if err != nil {
		return err
	}
	if chains, compact := state.CompactChains(); compact {
		fmt.Printf("PASS: signed sealer checkpoint is valid: %d chain heads, %d total seals; historical blocks are not retained here\n", chains, state.EntryCount())
	} else {
		fmt.Printf("PASS: sealer ledger and signatures are valid: %d entries\n", state.EntryCount())
	}
	return nil
}
