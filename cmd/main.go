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
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

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
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
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

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)

	// TLS compliance operator configuration flags
	var scanInterval time.Duration
	var cleanupInterval time.Duration
	var tlsCheckTimeout time.Duration
	var rateLimit float64
	var rateBurst int
	var includeNamespaces string
	var excludeNamespaces string
	var certExpiryWarningDays int
	var profileRefreshInterval time.Duration
	var workers int
	var maxRetries int
	var retryBackoff time.Duration
	var maxBackoff time.Duration
	var extraTLSPortsStr string
	var logFormat string

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	// Operator-specific flags
	flag.DurationVar(&scanInterval, "scan-interval", 1*time.Hour,
		"Interval for periodic TLS endpoint rescans")
	flag.DurationVar(&cleanupInterval, "cleanup-interval", 5*time.Minute,
		"Interval for cleaning up stale TLSComplianceReport resources")
	flag.DurationVar(&tlsCheckTimeout, "tls-check-timeout", 5*time.Second,
		"Timeout for individual TLS connection attempts")
	flag.Float64Var(&rateLimit, "rate-limit", 10.0,
		"Rate limit for TLS checks per second")
	flag.IntVar(&rateBurst, "rate-burst", 20,
		"Burst size for TLS check rate limiting")
	flag.StringVar(&includeNamespaces, "include-namespaces", "",
		"Comma-separated list of namespaces to exclusively monitor (overrides exclude-namespaces)")
	flag.StringVar(&excludeNamespaces, "exclude-namespaces", "",
		"Comma-separated list of namespaces to exclude from TLS monitoring")
	flag.IntVar(&certExpiryWarningDays, "cert-expiry-warning-days", 30,
		"Number of days before certificate expiry to emit a warning")
	flag.DurationVar(&profileRefreshInterval, "profile-refresh-interval", 5*time.Minute,
		"Interval for refreshing OpenShift TLS security profile configuration (OpenShift only)")
	flag.IntVar(&workers, "workers", 5,
		"Number of concurrent workers for periodic TLS scans (1-50)")
	flag.IntVar(&maxRetries, "max-retries", 3,
		"Maximum number of retries for transient TLS check failures (0-10)")
	flag.DurationVar(&retryBackoff, "retry-backoff", 30*time.Second,
		"Base backoff duration between retries (exponential: base * 2^attempt)")
	flag.DurationVar(&maxBackoff, "max-backoff", 5*time.Minute,
		"Maximum backoff duration between retries (caps exponential growth)")
	flag.StringVar(&extraTLSPortsStr, "extra-tls-ports", "",
		"Comma-separated list of additional port numbers to treat as TLS endpoints (e.g., 9443,6380,5671)")
	flag.StringVar(&logFormat, "log-format", "text",
		"Log output format: text or json")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// Apply environment variable overrides before logger creation so that
	// TLS_COMPLIANCE_LOG_FORMAT=json takes effect on the logger.
	envOverrides := resolveEnvConfig(flag.CommandLine, os.LookupEnv)

	// Validate log format (after env overrides may have changed it)
	if logFormat != "text" && logFormat != "json" {
		fmt.Fprintf(os.Stderr, "invalid --log-format value, must be text or json, got %q\n", logFormat)
		os.Exit(1)
	}

	if logFormat == "json" {
		opts.Development = false
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	for _, msg := range envOverrides {
		setupLog.Info(msg)
	}

	// Parse and apply extra TLS ports
	if extraTLSPortsStr != "" {
		ports, err := parsePortList(extraTLSPortsStr)
		if err != nil {
			setupLog.Error(err, "invalid --extra-tls-ports value")
			os.Exit(1)
		}
		endpoint.SetExtraTLSPorts(ports)
		setupLog.Info("extra TLS ports configured", "ports", extraTLSPortsStr)
	}

	// Validate workers flag
	if workers < 1 || workers > 50 {
		setupLog.Error(nil, "invalid --workers value, must be between 1 and 50", "workers", workers)
		os.Exit(1)
	}

	// Validate max-retries flag
	if maxRetries < 0 || maxRetries > 10 {
		setupLog.Error(nil, "invalid --max-retries value, must be between 0 and 10", "maxRetries", maxRetries)
		os.Exit(1)
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "tls-compliance.telco.openshift.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Detect Route API availability
	routeAPIAvailable := false
	restMapper := mgr.GetRESTMapper()
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

	// Detect OpenShift Config API availability for TLS security profile monitoring
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

	// Parse namespace filters
	includedNS := controller.ParseNamespaceList(includeNamespaces)
	excludedNS := controller.ParseNamespaceList(excludeNamespaces)

	if len(includedNS) > 0 && len(excludedNS) > 0 {
		setupLog.Info("WARNING: both --include-namespaces and --exclude-namespaces are set; --include-namespaces takes precedence")
	}

	// Initialize TLS checker with rate limiting
	baseChecker := tlscheck.NewTLSChecker(tlsCheckTimeout)
	checker := tlscheck.NewRateLimitedChecker(baseChecker, rateLimit, rateBurst)

	setupLog.Info("TLS checker configured",
		"timeout", tlsCheckTimeout,
		"rateLimit", rateLimit,
		"rateBurst", rateBurst,
		"scanInterval", scanInterval,
		"cleanupInterval", cleanupInterval,
		"certExpiryWarningDays", certExpiryWarningDays,
		"includeNamespaces", includedNS,
		"excludeNamespaces", excludedNS,
		"workers", workers,
		"maxRetries", maxRetries,
		"retryBackoff", retryBackoff)

	// Set up signal-aware context for the operator lifecycle
	ctx := ctrl.SetupSignalHandler()

	// Set up the endpoint controller
	endpointReconciler := &controller.EndpointReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		TLSChecker:        checker,
		Recorder:          mgr.GetEventRecorderFor("tls-compliance-controller"), //nolint:staticcheck
		IncludeNamespaces: includedNS,
		ExcludeNamespaces: excludedNS,
		CertExpiryDays:    certExpiryWarningDays,
		RouteAPIAvailable: routeAPIAvailable,
		ProfileFetcher:    profileFetcher,
		Workers:           workers,
		MaxRetries:        maxRetries,
		RetryBackoff:      retryBackoff,
		MaxBackoff:        maxBackoff,
		ManagerCtx:        ctx,
	}

	if err = endpointReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Endpoint")
		os.Exit(1)
	}

	// Start background loops
	endpointReconciler.StartPeriodicScan(ctx, scanInterval)
	endpointReconciler.StartCleanupLoop(ctx, cleanupInterval)
	if profileFetcher != nil {
		profileFetcher.StartPeriodicRefresh(ctx, profileRefreshInterval)
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
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
	{"TLS_COMPLIANCE_LOG_FORMAT", "log-format"},
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
