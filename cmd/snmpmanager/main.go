package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/me262/snmp-manager/internal/api"
	"github.com/me262/snmp-manager/internal/config"
	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/mib"
	"github.com/me262/snmp-manager/internal/output"
	"github.com/me262/snmp-manager/internal/pipeline"
	"github.com/me262/snmp-manager/internal/poller"
	"github.com/me262/snmp-manager/internal/telemetry"
	"github.com/me262/snmp-manager/internal/trap"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Parse CLI flags
	configFile := flag.String("config", "configs/config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SNMP Manager v%s (built: %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Setup logger
	log := telemetry.SetupLogger(cfg.Server.LogLevel, cfg.Server.LogFormat)
	log.Info().
		Str("version", version).
		Str("name", cfg.Server.Name).
		Str("config", *configFile).
		Msg("🚀 SNMP Manager starting")

	// Create root context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Initialize components ──────────────────────────────────────

	// 1. MIB Resolver
	resolver := mib.NewResolver(log)

	// Load system MIB files via gosmi (adds thousands of OID translations)
	if cfg.MIB.LoadSystemMIBs {
		resolver.LoadSystemMIBs(cfg.MIB.Directories...)
	}

	log.Info().Int("oids", resolver.Count()).Msg("MIB resolver initialized")

	// 2. Device Registry
	registry := device.NewRegistry(log)
	if err := registry.LoadFromConfig(cfg.Devices); err != nil {
		log.Fatal().Err(err).Msg("failed to load devices")
	}

	// 3. Build outputs — check for UI-managed overrides first
	managedOutputs, err := config.LoadManagedOutputs(*configFile)
	if err != nil {
		log.Warn().Err(err).Msg("failed to load managed outputs, using config defaults")
	}
	if managedOutputs != nil {
		log.Info().Int("count", len(managedOutputs)).Msg("loaded UI-managed output configuration")
		cfg.Outputs = managedOutputs
	}

	var outputs []pipeline.Output
	for _, outCfg := range cfg.Outputs {
		if !outCfg.Enabled {
			continue
		}
		switch outCfg.Type {
		case "syslog":
			protocol := outCfg.Protocol
			if protocol == "" {
				protocol = "udp"
			}
			format := outCfg.Format
			if format == "" {
				format = "cef"
			}
			out := output.NewSyslogOutput(log, outCfg.Address, protocol, format)
			outputs = append(outputs, out)
			log.Info().Str("address", outCfg.Address).Str("format", format).Msg("syslog output configured")

		case "file":
			out := output.NewFileOutput(log, outCfg.Path, outCfg.MaxSizeMB, outCfg.MaxBackups, outCfg.Compress)
			outputs = append(outputs, out)
			log.Info().Str("path", outCfg.Path).Msg("file output configured")

		case "stdout":
			out := output.NewStdoutOutput(log)
			outputs = append(outputs, out)
			log.Info().Msg("stdout output configured")

		case "http":
			url := outCfg.URL
			if url == "" {
				url = outCfg.Address
			}
			out := output.NewHTTPOutput(log, url, outCfg.Headers, outCfg.TLSSkipVerify)
			outputs = append(outputs, out)
			log.Info().Str("url", url).Msg("http output configured")

		case "elasticsearch":
			addrs := outCfg.Addresses
			if len(addrs) == 0 && outCfg.Address != "" {
				addrs = []string{outCfg.Address}
			}
			out := output.NewElasticsearchOutput(log, addrs, outCfg.Index, outCfg.Username, outCfg.Password, outCfg.TLSSkipVerify)
			outputs = append(outputs, out)
			log.Info().Strs("addresses", addrs).Str("index", outCfg.Index).Msg("elasticsearch output configured")

		case "tcp":
			out := output.NewTCPOutput(log, outCfg.Address)
			outputs = append(outputs, out)
			log.Info().Str("address", outCfg.Address).Msg("tcp output configured")
		}
	}

	// If no outputs configured, use stdout
	if len(outputs) == 0 {
		outputs = append(outputs, output.NewStdoutOutput(log))
		log.Warn().Msg("no outputs configured, using stdout")
	}

	// 4. Pipeline
	normalizer := pipeline.NewNormalizer(resolver, log)
	enricher := pipeline.NewEnricher(log)

	pipe := pipeline.NewPipeline(log, pipeline.PipelineConfig{
		BufferSize:    cfg.Pipeline.BufferSize,
		Workers:       cfg.Pipeline.Workers,
		FlushInterval: cfg.Pipeline.FlushInterval,
	}, normalizer, enricher, outputs)

	// 5. Poller
	poll := poller.New(log, cfg.Poller, registry, resolver, pipe)

	// 6. Trap Listener
	trapListener := trap.NewListener(log, cfg.TrapReceiver, registry, resolver, pipe)

	// 7. API Server
	apiServer := api.NewServer(log, cfg.API, cfg, *configFile, registry, resolver, poll, trapListener, pipe, cfg.Outputs)

	// ── Start all components ───────────────────────────────────────

	var wg sync.WaitGroup

	// Start pipeline
	wg.Add(1)
	go func() {
		defer wg.Done()
		pipe.Run(ctx)
	}()

	// Start poller
	wg.Add(1)
	go func() {
		defer wg.Done()
		poll.Run(ctx)
	}()

	// Start trap listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := trapListener.Run(ctx); err != nil {
			log.Error().Err(err).Msg("trap listener error")
		}
	}()

	// Start API server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := apiServer.Run(ctx); err != nil {
			log.Error().Err(err).Msg("API server error")
		}
	}()

	// ── Print startup summary ──────────────────────────────────────

	log.Info().
		Int("devices", registry.Count()).
		Int("outputs", len(outputs)).
		Int("poller_workers", cfg.Poller.Workers).
		Bool("trap_receiver", cfg.TrapReceiver.Enabled).
		Bool("api_enabled", cfg.API.Enabled).
		Msg("✅ SNMP Manager is running")

	// ── Wait for shutdown signal ───────────────────────────────────

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("⏹️  Shutdown signal received")

	// Cancel context to stop all components
	cancel()

	// Wait for clean shutdown
	wg.Wait()

	log.Info().Msg("👋 SNMP Manager stopped gracefully")
}
