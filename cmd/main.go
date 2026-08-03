/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/internal/controller"
	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
	"github.com/sebrandon1/tls-compliance-operator/pkg/fips"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlsprofile"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

type operatorConfig struct {
	metricsAddr     string
	metricsCertPath string
	metricsCertName string
	metricsCertKey  string
	webhookCertPath string
	webhookCertName string
	webhookCertKey  string
	probeAddr       string

	enableLeaderElection bool
	secureMetrics        bool
	enableHTTP2          bool

	scanInterval           time.Duration
	cleanupInterval        time.Duration
	tlsCheckTimeout        time.Duration
	rateLimit              float64
	rateBurst              int
	includeNamespaces      string
	excludeNamespaces      string
	certExpiryWarningDays  int
	profileRefreshInterval time.Duration
	workers                int
	maxRetries             int
	retryBackoff           time.Duration
	maxBackoff             time.Duration
	extraTLSPortsStr       string
	scanAllPorts           bool
	clientCertPath         string
	clientKeyPath          string
	enumerateCiphers       bool
	namespaceRateLimitsStr string
	metricsPerEndpoint     bool
	reportRetentionDays    int
	logFormat              string
	runOnce                bool
	outputFormat           string
	outputFile             string

	zapOpts zap.Options
}

func parseFlags() *operatorConfig {
	cfg := &operatorConfig{}

	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&cfg.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&cfg.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&cfg.webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&cfg.webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&cfg.webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&cfg.metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&cfg.metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&cfg.metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&cfg.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	flag.DurationVar(&cfg.scanInterval, "scan-interval", 1*time.Hour,
		"Interval for periodic TLS endpoint rescans")
	flag.DurationVar(&cfg.cleanupInterval, "cleanup-interval", 5*time.Minute,
		"Interval for cleaning up stale TLSComplianceReport resources")
	flag.DurationVar(&cfg.tlsCheckTimeout, "tls-check-timeout", 5*time.Second,
		"Timeout for individual TLS connection attempts")
	flag.Float64Var(&cfg.rateLimit, "rate-limit", 10.0,
		"Rate limit for TLS checks per second")
	flag.IntVar(&cfg.rateBurst, "rate-burst", 20,
		"Burst size for TLS check rate limiting")
	flag.StringVar(&cfg.includeNamespaces, "include-namespaces", "",
		"Comma-separated list of namespaces to exclusively monitor (overrides exclude-namespaces)")
	flag.StringVar(&cfg.excludeNamespaces, "exclude-namespaces", "",
		"Comma-separated list of namespaces to exclude from TLS monitoring")
	flag.IntVar(&cfg.certExpiryWarningDays, "cert-expiry-warning-days", 30,
		"Number of days before certificate expiry to emit a warning")
	flag.DurationVar(&cfg.profileRefreshInterval, "profile-refresh-interval", 5*time.Minute,
		"Interval for refreshing OpenShift TLS security profile configuration (OpenShift only)")
	flag.IntVar(&cfg.workers, "workers", 5,
		"Number of concurrent workers for periodic TLS scans (1-50)")
	flag.IntVar(&cfg.maxRetries, "max-retries", 3,
		"Maximum number of retries for transient TLS check failures (0-10)")
	flag.DurationVar(&cfg.retryBackoff, "retry-backoff", 30*time.Second,
		"Base backoff duration between retries (exponential: base * 2^attempt)")
	flag.DurationVar(&cfg.maxBackoff, "max-backoff", 5*time.Minute,
		"Maximum backoff duration between retries (caps exponential growth)")
	flag.StringVar(&cfg.extraTLSPortsStr, "extra-tls-ports", "",
		"Comma-separated list of additional port numbers to treat as TLS endpoints (e.g., 9443,6380,5671)")
	flag.BoolVar(&cfg.scanAllPorts, "scan-all-ports", false,
		"Scan all declared TCP container ports on pods, not just known TLS ports")
	flag.StringVar(&cfg.clientCertPath, "client-cert", "",
		"Path to a PEM-encoded client certificate for mTLS endpoint probing")
	flag.StringVar(&cfg.clientKeyPath, "client-key", "",
		"Path to a PEM-encoded client private key for mTLS endpoint probing")
	flag.BoolVar(&cfg.enumerateCiphers, "enumerate-ciphers", true,
		"Enumerate all supported cipher suites per TLS version (disable for faster scans)")
	flag.StringVar(&cfg.namespaceRateLimitsStr, "namespace-rate-limits", "",
		"Per-namespace TLS check rate limits (e.g., production=2.0,staging=10.0)")
	flag.BoolVar(&cfg.metricsPerEndpoint, "metrics-per-endpoint", true,
		"Emit per-endpoint Prometheus metrics (disable for large clusters to reduce cardinality)")
	flag.IntVar(&cfg.reportRetentionDays, "report-retention-days", 0,
		"Delete TLSComplianceReport CRs with no activity for this many days (0 = disabled)")
	flag.StringVar(&cfg.logFormat, "log-format", "text",
		"Log output format: text or json")
	flag.BoolVar(&cfg.runOnce, "run-once", false,
		"Perform a single scan of all endpoints and exit (0=compliant, 1=non-compliant, 2=error)")
	flag.StringVar(&cfg.outputFormat, "output-format", "",
		"Write scan results in this format (csv, json, yaml, junit, markdown); defaults to stdout")
	flag.StringVar(&cfg.outputFile, "output-file", "",
		"Path to write scan results (requires --output-format)")

	cfg.zapOpts = zap.Options{Development: true}
	cfg.zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()

	envOverrides := resolveEnvConfig(flag.CommandLine, os.LookupEnv)

	if cfg.logFormat != "text" && cfg.logFormat != "json" {
		fmt.Fprintf(os.Stderr, "invalid --log-format value, must be text or json, got %q\n", cfg.logFormat)
		os.Exit(1)
	}

	if cfg.logFormat == "json" {
		cfg.zapOpts.Development = false
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&cfg.zapOpts)))

	for _, msg := range envOverrides {
		setupLog.Info(msg)
	}

	return cfg
}

func validateConfig(cfg *operatorConfig) {
	if cfg.extraTLSPortsStr != "" {
		ports, err := parsePortList(cfg.extraTLSPortsStr)
		if err != nil {
			setupLog.Error(err, "invalid --extra-tls-ports value")
			os.Exit(1)
		}
		endpoint.SetExtraTLSPorts(ports)
		setupLog.Info("extra TLS ports configured", "ports", cfg.extraTLSPortsStr)
	}

	endpoint.SetScanAllPorts(cfg.scanAllPorts)
	if cfg.scanAllPorts {
		setupLog.Info("scan-all-ports enabled: all declared TCP container ports on pods will be scanned")
	}

	if cfg.workers < 1 || cfg.workers > 50 {
		setupLog.Error(nil, "invalid --workers value, must be between 1 and 50", "workers", cfg.workers)
		os.Exit(1)
	}

	if cfg.maxRetries < 0 || cfg.maxRetries > 10 {
		setupLog.Error(nil, "invalid --max-retries value, must be between 0 and 10", "maxRetries", cfg.maxRetries)
		os.Exit(1)
	}

	if cfg.reportRetentionDays < 0 {
		setupLog.Error(nil, "invalid --report-retention-days value, must be non-negative", "reportRetentionDays", cfg.reportRetentionDays)
		os.Exit(1)
	}

	if cfg.outputFormat != "" {
		switch cfg.outputFormat {
		case "csv", "json", "yaml", "junit", "markdown":
		default:
			setupLog.Error(nil, "invalid --output-format value", "format", cfg.outputFormat,
				"valid", "csv, json, yaml, junit, markdown")
			os.Exit(1)
		}
	}
	if cfg.outputFile != "" && cfg.outputFormat == "" {
		setupLog.Error(nil, "--output-file requires --output-format to be set")
		os.Exit(1)
	}
}

func buildTLSOpts(cfg *operatorConfig) []func(*tls.Config) {
	var tlsOpts []func(*tls.Config)

	// Disabling http/2 prevents the HTTP/2 Stream Cancellation and Rapid Reset CVEs.
	// https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// https://github.com/advisories/GHSA-4374-p667-p6c8
	if !cfg.enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			setupLog.Info("disabling http/2")
			c.NextProtos = []string{"http/1.1"}
		})
	}

	return tlsOpts
}

func setupManager(ctx context.Context, cfg *operatorConfig) (ctrl.Manager, *controller.EndpointReconciler) {
	tlsOpts := buildTLSOpts(cfg)

	webhookServerOptions := webhook.Options{
		TLSOpts: tlsOpts,
	}
	if len(cfg.webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", cfg.webhookCertPath, "webhook-cert-name", cfg.webhookCertName, "webhook-cert-key", cfg.webhookCertKey)
		webhookServerOptions.CertDir = cfg.webhookCertPath
		webhookServerOptions.CertName = cfg.webhookCertName
		webhookServerOptions.KeyName = cfg.webhookCertKey
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   cfg.metricsAddr,
		SecureServing: cfg.secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if cfg.secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if len(cfg.metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", cfg.metricsCertPath, "metrics-cert-name", cfg.metricsCertName, "metrics-cert-key", cfg.metricsCertKey)
		metricsServerOptions.CertDir = cfg.metricsCertPath
		metricsServerOptions.CertName = cfg.metricsCertName
		metricsServerOptions.KeyName = cfg.metricsCertKey
	}

	mgrOpts := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhook.NewServer(webhookServerOptions),
		HealthProbeBindAddress: cfg.probeAddr,
		LeaderElection:         cfg.enableLeaderElection,
		LeaderElectionID:       "tls-compliance.telco.openshift.io",
	}
	if cfg.runOnce {
		mgrOpts.LeaderElection = false
		mgrOpts.HealthProbeBindAddress = "0"
		mgrOpts.Metrics.BindAddress = "0"
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOpts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	restMapper := mgr.GetRESTMapper()

	routeAPIAvailable := false
	_, err = restMapper.RESTMapping(schema.GroupKind{
		Group: "route.openshift.io",
		Kind:  "Route",
	}, "v1")
	if err == nil {
		routeAPIAvailable = true
		setupLog.Info("OpenShift Route API detected, enabling Route monitoring")
	} else {
		setupLog.Info("OpenShift Route API not detected, skipping Route monitoring")
	}

	var gatewayGVKs []schema.GroupVersionKind
	for _, gvk := range []struct {
		group, version, kind string
	}{
		{"gateway.networking.k8s.io", "v1", "HTTPRoute"},
		{"gateway.networking.k8s.io", "v1alpha2", "TLSRoute"},
		{"gateway.networking.k8s.io", "v1", "Gateway"},
	} {
		_, err = restMapper.RESTMapping(schema.GroupKind{Group: gvk.group, Kind: gvk.kind}, gvk.version)
		if err == nil {
			gatewayGVKs = append(gatewayGVKs, schema.GroupVersionKind{Group: gvk.group, Version: gvk.version, Kind: gvk.kind})
			setupLog.Info("Gateway API resource detected", "kind", gvk.kind)
		}
	}
	if len(gatewayGVKs) == 0 {
		setupLog.Info("Gateway API not detected, skipping Gateway resource monitoring")
	}

	var profileFetcher *tlsprofile.Fetcher
	_, err = restMapper.RESTMapping(schema.GroupKind{
		Group: "config.openshift.io",
		Kind:  "APIServer",
	}, "v1")
	if err == nil {
		setupLog.Info("OpenShift Config API detected, enabling TLS security profile monitoring")
		profileFetcher = tlsprofile.NewFetcher(mgr.GetClient())
	} else {
		setupLog.Info("OpenShift Config API not detected, skipping TLS security profile monitoring")
	}

	fipsEnabled := fips.Detect()
	if fipsEnabled {
		setupLog.Info("FIPS mode detected, ML-KEM key exchange is unavailable")
	} else {
		setupLog.Info("FIPS mode not detected")
	}
	metrics.RecordFIPSMode(fipsEnabled)

	includedNS := controller.ParseNamespaceList(cfg.includeNamespaces)
	excludedNS := controller.ParseNamespaceList(cfg.excludeNamespaces)
	if len(includedNS) > 0 && len(excludedNS) > 0 {
		setupLog.Info("WARNING: both --include-namespaces and --exclude-namespaces are set; --include-namespaces takes precedence")
	}

	baseChecker := tlscheck.NewTLSChecker(cfg.tlsCheckTimeout)
	baseChecker.EnumerateCiphers = cfg.enumerateCiphers
	if cfg.clientCertPath != "" && cfg.clientKeyPath != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.clientCertPath, cfg.clientKeyPath)
		if err != nil {
			setupLog.Error(err, "failed to load client certificate for mTLS probing")
			os.Exit(1)
		}
		baseChecker.ClientCert = &clientCert
		setupLog.Info("mTLS client certificate configured for endpoint probing",
			"certPath", cfg.clientCertPath)
	}
	checker := tlscheck.NewRateLimitedChecker(baseChecker, cfg.rateLimit, cfg.rateBurst)

	setupLog.Info("TLS checker configured",
		"timeout", cfg.tlsCheckTimeout,
		"rateLimit", cfg.rateLimit,
		"rateBurst", cfg.rateBurst,
		"scanInterval", cfg.scanInterval,
		"cleanupInterval", cfg.cleanupInterval,
		"certExpiryWarningDays", cfg.certExpiryWarningDays,
		"includeNamespaces", includedNS,
		"excludeNamespaces", excludedNS,
		"workers", cfg.workers,
		"maxRetries", cfg.maxRetries,
		"retryBackoff", cfg.retryBackoff)

	var nsLimiters map[string]*rate.Limiter
	var defaultNSLimiter *rate.Limiter
	if cfg.namespaceRateLimitsStr != "" {
		nsLimiters = make(map[string]*rate.Limiter)
		for _, entry := range strings.Split(cfg.namespaceRateLimitsStr, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
			if len(parts) != 2 {
				setupLog.Error(nil, "invalid --namespace-rate-limits entry", "entry", entry)
				os.Exit(1)
			}
			rateVal, err := strconv.ParseFloat(parts[1], 64)
			if err != nil {
				setupLog.Error(err, "invalid rate in --namespace-rate-limits", "namespace", parts[0])
				os.Exit(1)
			}
			nsLimiters[parts[0]] = rate.NewLimiter(rate.Limit(rateVal), int(rateVal)+1)
		}
		defaultNSLimiter = rate.NewLimiter(rate.Limit(cfg.rateLimit), cfg.rateBurst)
		setupLog.Info("per-namespace rate limits configured", "namespaces", cfg.namespaceRateLimitsStr)
	}

	endpointReconciler := &controller.EndpointReconciler{
		Client:                mgr.GetClient(),
		APIReader:             mgr.GetAPIReader(),
		Scheme:                mgr.GetScheme(),
		TLSChecker:            checker,
		Recorder:              mgr.GetEventRecorderFor("tls-compliance-controller"), //nolint:staticcheck // migrating to events API is a separate task
		IncludeNamespaces:     includedNS,
		ExcludeNamespaces:     excludedNS,
		CertExpiryDays:        cfg.certExpiryWarningDays,
		RouteAPIAvailable:     routeAPIAvailable,
		GatewayAPIAvailable:   len(gatewayGVKs) > 0,
		GatewayGVKs:           gatewayGVKs,
		ProfileFetcher:        profileFetcher,
		Workers:               cfg.workers,
		MaxRetries:            cfg.maxRetries,
		RetryBackoff:          cfg.retryBackoff,
		MaxBackoff:            cfg.maxBackoff,
		MetricsPerEndpoint:    cfg.metricsPerEndpoint,
		ReportRetentionDays:   cfg.reportRetentionDays,
		FIPSEnabled:           fipsEnabled,
		NamespaceRateLimiters: nsLimiters,
		DefaultNamespaceRate:  defaultNSLimiter,
		ManagerCtx:            ctx,
	}

	if cfg.runOnce {
		endpointReconciler.RunOnce = true
		endpointReconciler.RunOnceDone = make(chan error, 1)
	}

	if err = endpointReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Endpoint")
		os.Exit(1)
	}

	endpointReconciler.StartPeriodicScan(ctx, cfg.scanInterval, mgr.Elected())
	if !cfg.runOnce {
		endpointReconciler.StartCleanupLoop(ctx, cfg.cleanupInterval)
		if profileFetcher != nil {
			profileFetcher.StartPeriodicRefresh(ctx, cfg.profileRefreshInterval)
		}
	}

	if cfg.webhookCertPath != "" {
		if err = securityv1alpha1.SetupTLSComplianceTargetWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "TLSComplianceTarget")
			os.Exit(1)
		}
		setupLog.Info("TLSComplianceTarget validating webhook enabled")
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", func(_ *http.Request) error {
		if !endpointReconciler.InitialScanDone.Load() {
			return fmt.Errorf("initial TLS scan not yet completed")
		}
		return nil
	}); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	return mgr, endpointReconciler
}

func main() {
	cfg := parseFlags()
	validateConfig(cfg)

	ctx, cancel := context.WithCancel(ctrl.SetupSignalHandler())
	defer cancel()

	mgr, reconciler := setupManager(ctx, cfg)

	if cfg.runOnce {
		runOnceAndExit(ctx, cancel, mgr, reconciler, cfg)
		return
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		cancel()
		os.Exit(1)
	}
}

func runOnceAndExit(ctx context.Context, cancel context.CancelFunc, mgr ctrl.Manager, reconciler *controller.EndpointReconciler, cfg *operatorConfig) {
	go func() {
		if err := mgr.Start(ctx); err != nil {
			setupLog.Error(err, "manager exited with error")
		}
	}()

	scanErr := <-reconciler.RunOnceDone

	exitCode := 0
	if scanErr != nil {
		setupLog.Error(scanErr, "scan failed")
		exitCode = 2
	}

	var reportList securityv1alpha1.TLSComplianceReportList
	if err := mgr.GetClient().List(ctx, &reportList); err != nil {
		setupLog.Error(err, "failed to list reports after scan")
		cancel()
		os.Exit(2)
	}

	reports := reportList.Items
	setupLog.Info("run-once scan results", "total", len(reports))

	if exitCode == 0 && export.HasNonCompliantReports(reports) {
		exitCode = 1
		setupLog.Info("non-compliant endpoints detected", "exitCode", exitCode)
	}

	if cfg.outputFormat != "" {
		if err := writeRunOnceOutput(reports, cfg); err != nil {
			setupLog.Error(err, "failed to write output")
			if exitCode == 0 {
				exitCode = 2
			}
		}
	}

	cancel()
	os.Exit(exitCode)
}

func writeRunOnceOutput(reports []securityv1alpha1.TLSComplianceReport, cfg *operatorConfig) error {
	var w io.Writer = os.Stdout
	if cfg.outputFile != "" {
		f, err := os.Create(cfg.outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
		setupLog.Info("writing results", "file", cfg.outputFile, "format", cfg.outputFormat)
	}

	switch cfg.outputFormat {
	case "csv":
		return export.WriteCSV(w, reports)
	case "json":
		return export.WriteJSON(w, reports)
	case "yaml":
		return export.WriteYAML(w, reports)
	case "junit":
		return export.WriteJUnit(w, reports)
	case "markdown":
		return export.WriteMarkdown(w, reports)
	default:
		return fmt.Errorf("unknown output format: %s", cfg.outputFormat)
	}
}

// envFlagMapping maps environment variable names to their corresponding flag names.
var envFlagMapping = []struct {
	envVar   string
	flagName string
}{
	{"TLS_COMPLIANCE_SCAN_INTERVAL", "scan-interval"},
	{"TLS_COMPLIANCE_CLEANUP_INTERVAL", "cleanup-interval"},
	{"TLS_COMPLIANCE_CHECK_TIMEOUT", "tls-check-timeout"},
	{"TLS_COMPLIANCE_RATE_LIMIT", "rate-limit"},
	{"TLS_COMPLIANCE_RATE_BURST", "rate-burst"},
	{"TLS_COMPLIANCE_WORKERS", "workers"},
	{"TLS_COMPLIANCE_INCLUDE_NAMESPACES", "include-namespaces"},
	{"TLS_COMPLIANCE_EXCLUDE_NAMESPACES", "exclude-namespaces"},
	{"TLS_COMPLIANCE_CERT_EXPIRY_WARNING_DAYS", "cert-expiry-warning-days"},
	{"TLS_COMPLIANCE_PROFILE_REFRESH_INTERVAL", "profile-refresh-interval"},
	{"TLS_COMPLIANCE_MAX_RETRIES", "max-retries"},
	{"TLS_COMPLIANCE_RETRY_BACKOFF", "retry-backoff"},
	{"TLS_COMPLIANCE_MAX_BACKOFF", "max-backoff"},
	{"TLS_COMPLIANCE_EXTRA_TLS_PORTS", "extra-tls-ports"},
	{"TLS_COMPLIANCE_SCAN_ALL_PORTS", "scan-all-ports"},
	{"TLS_COMPLIANCE_CLIENT_CERT", "client-cert"},
	{"TLS_COMPLIANCE_CLIENT_KEY", "client-key"},
	{"TLS_COMPLIANCE_REPORT_RETENTION_DAYS", "report-retention-days"},
	{"TLS_COMPLIANCE_LOG_FORMAT", "log-format"},
	{"TLS_COMPLIANCE_RUN_ONCE", "run-once"},
	{"TLS_COMPLIANCE_OUTPUT_FORMAT", "output-format"},
	{"TLS_COMPLIANCE_OUTPUT_FILE", "output-file"},
}

// resolveEnvConfig applies environment variable overrides to flags that were not
// explicitly set on the command line. Precedence: CLI flag > env var > default.
// It returns log messages describing which overrides were applied.
func resolveEnvConfig(fs *flag.FlagSet, lookupEnv func(string) (string, bool)) []string {
	// Build set of flags explicitly set via CLI
	explicitlySet := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		explicitlySet[f.Name] = true
	})

	var messages []string

	for _, mapping := range envFlagMapping {
		if explicitlySet[mapping.flagName] {
			messages = append(messages, fmt.Sprintf("config: %s set via CLI flag", mapping.flagName))
			continue
		}

		envVal, ok := lookupEnv(mapping.envVar)
		if !ok || envVal == "" {
			messages = append(messages, fmt.Sprintf("config: %s using default", mapping.flagName))
			continue
		}

		f := fs.Lookup(mapping.flagName)
		if f == nil {
			continue
		}

		// Validate the value before applying
		if err := validateEnvValue(mapping.flagName, envVal); err != nil {
			messages = append(messages, fmt.Sprintf("config: ignoring invalid %s=%q: %v", mapping.envVar, envVal, err))
			continue
		}

		if err := f.Value.Set(envVal); err != nil {
			messages = append(messages, fmt.Sprintf("config: ignoring invalid %s=%q: %v", mapping.envVar, envVal, err))
			continue
		}

		messages = append(messages, fmt.Sprintf("config: %s set via env %s=%s", mapping.flagName, mapping.envVar, envVal))
	}

	return messages
}

// validateEnvValue performs type-appropriate validation for known flag types.
func validateEnvValue(flagName, value string) error {
	switch flagName {
	case "scan-interval", "cleanup-interval", "tls-check-timeout", "profile-refresh-interval", "retry-backoff", "max-backoff":
		if _, err := time.ParseDuration(value); err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
	case "rate-limit":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return fmt.Errorf("invalid float: %w", err)
		}
	case "rate-burst":
		return validateIntRange(value, 1, 1000)
	case "cert-expiry-warning-days":
		return validateIntRange(value, 1, 365)
	case "workers":
		return validateIntRange(value, 1, 50)
	case "max-retries":
		return validateIntRange(value, 0, 10)
	case "extra-tls-ports":
		_, err := parsePortList(value)
		return err
	case "log-format":
		if value != "text" && value != "json" {
			return fmt.Errorf("must be text or json, got %q", value)
		}
	case "run-once", "scan-all-ports":
		if value != "true" && value != "false" && value != "1" && value != "0" {
			return fmt.Errorf("must be true or false, got %q", value)
		}
	case "report-retention-days":
		return validateIntRange(value, 0, 3650)
	case "output-format":
		switch value {
		case "csv", "json", "yaml", "junit", "markdown":
		default:
			return fmt.Errorf("must be csv, json, yaml, junit, or markdown, got %q", value)
		}
	}
	return nil
}

func validateIntRange(value string, min, max int) error {
	v, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("invalid integer: %w", err)
	}
	if v < min || v > max {
		return fmt.Errorf("must be between %d and %d, got %d", min, max, v)
	}
	return nil
}

func parsePortList(value string) (map[int32]bool, error) {
	ports := map[int32]bool{}
	for _, s := range strings.Split(value, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", s, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", p)
		}
		ports[int32(p)] = true
	}
	return ports, nil
}
