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
	"os"
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
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
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
	var excludeNamespaces string
	var certExpiryWarningDays int

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
	flag.StringVar(&excludeNamespaces, "exclude-namespaces", "",
		"Comma-separated list of namespaces to exclude from TLS monitoring")
	flag.IntVar(&certExpiryWarningDays, "cert-expiry-warning-days", 30,
		"Number of days before certificate expiry to emit a warning")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

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

	// Parse excluded namespaces
	var excludedNS []string
	if excludeNamespaces != "" {
		for _, ns := range strings.Split(excludeNamespaces, ",") {
			trimmed := strings.TrimSpace(ns)
			if trimmed != "" {
				excludedNS = append(excludedNS, trimmed)
			}
		}
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
		"excludeNamespaces", excludedNS)

	// Set up the endpoint controller
	endpointReconciler := &controller.EndpointReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		TLSChecker:        checker,
		Recorder:          mgr.GetEventRecorderFor("tls-compliance-controller"), //nolint:staticcheck
		ExcludeNamespaces: excludedNS,
		CertExpiryDays:    certExpiryWarningDays,
		RouteAPIAvailable: routeAPIAvailable,
	}

	if err = endpointReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Endpoint")
		os.Exit(1)
	}

	// Start background loops
	ctx := ctrl.SetupSignalHandler()
	endpointReconciler.StartPeriodicScan(ctx, scanInterval)
	endpointReconciler.StartCleanupLoop(ctx, cleanupInterval)

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
