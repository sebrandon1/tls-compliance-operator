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

package v1alpha1

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func TestTLSComplianceTargetPortAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set; run with envtest binaries to test admission")
	}

	root := filepath.Join("..", "..")
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(root, "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join(root, "config", "webhook", "manifests.yaml")},
		},
	}
	config, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})

	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add API types to scheme: %v", err)
	}
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    env.WebhookInstallOptions.LocalServingPort,
			Host:    env.WebhookInstallOptions.LocalServingHost,
			CertDir: env.WebhookInstallOptions.LocalServingCertDir,
		}),
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	if err := SetupTLSComplianceTargetWebhookWithManager(mgr); err != nil {
		t.Fatalf("register TLSComplianceTarget webhook: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	managerDone := make(chan error, 1)
	go func() {
		managerDone <- mgr.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-managerDone; err != nil {
			t.Errorf("stop manager: %v", err)
		}
		targetClientMu.Lock()
		targetClient = nil
		targetClientMu.Unlock()
	})

	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()
	for {
		if err := mgr.GetWebhookServer().StartedChecker()(nil); err == nil {
			break
		}
		select {
		case <-startCtx.Done():
			t.Fatalf("wait for webhook server: %v", startCtx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !mgr.GetCache().WaitForCacheSync(startCtx) {
		t.Fatalf("wait for manager cache sync: %v", startCtx.Err())
	}

	apiClient, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("create API client: %v", err)
	}

	t.Run("omitted port defaults to 443", func(t *testing.T) {
		target := &TLSComplianceTarget{}
		target.Name = "omitted-port"
		target.Spec.Host = "omitted.example.com"
		if err := apiClient.Create(context.Background(), target); err != nil {
			t.Fatalf("create target without a port: %v", err)
		}

		var created TLSComplianceTarget
		if err := apiClient.Get(context.Background(), client.ObjectKey{Name: target.Name}, &created); err != nil {
			t.Fatalf("get created target: %v", err)
		}
		if got := created.Spec.Port; got == nil || *got != 443 {
			t.Fatalf("created port = %v, want 443", got)
		}
	})

	t.Run("explicit zero is rejected", func(t *testing.T) {
		zero := int32(0)
		target := &TLSComplianceTarget{}
		target.Name = "zero-port"
		target.Spec.Host = "zero.example.com"
		target.Spec.Port = &zero
		if err := apiClient.Create(context.Background(), target); !apierrors.IsInvalid(err) {
			t.Fatalf("create target with port zero error = %v, want an invalid resource error", err)
		}
	})

	t.Run("custom port is preserved", func(t *testing.T) {
		port := int32(8443)
		target := &TLSComplianceTarget{}
		target.Name = "custom-port"
		target.Spec.Host = "custom.example.com"
		target.Spec.Port = &port
		if err := apiClient.Create(context.Background(), target); err != nil {
			t.Fatalf("create target with custom port: %v", err)
		}

		var created TLSComplianceTarget
		if err := apiClient.Get(context.Background(), client.ObjectKey{Name: target.Name}, &created); err != nil {
			t.Fatalf("get created target: %v", err)
		}
		if got := created.Spec.Port; got == nil || *got != port {
			t.Fatalf("created port = %v, want %d", got, port)
		}
	})
}
