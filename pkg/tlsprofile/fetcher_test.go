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

package tlsprofile

import (
	"context"
	"fmt"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestSetProfile_RoundTrip(t *testing.T) {
	f := NewFetcher(nil)

	profile := PredefinedProfiles[ProfileTypeModern]
	f.setProfile(ComponentAPIServer, &profile)

	got := f.GetProfile(ComponentAPIServer)
	if got.Type != ProfileTypeModern {
		t.Errorf("expected Modern, got %s", got.Type)
	}
	if got.MinTLSVersion != VersionTLS13 {
		t.Errorf("expected VersionTLS13, got %s", got.MinTLSVersion)
	}
}

func TestSetProfile_OverwritesPrevious(t *testing.T) {
	f := NewFetcher(nil)

	old := PredefinedProfiles[ProfileTypeOld]
	f.setProfile(ComponentAPIServer, &old)

	modern := PredefinedProfiles[ProfileTypeModern]
	f.setProfile(ComponentAPIServer, &modern)

	got := f.GetProfile(ComponentAPIServer)
	if got.Type != ProfileTypeModern {
		t.Errorf("expected Modern after overwrite, got %s", got.Type)
	}
}

func TestGetProfile_DefaultsToIntermediate(t *testing.T) {
	f := NewFetcher(nil)

	got := f.GetProfile(ComponentAPIServer)
	if got.Type != ProfileTypeIntermediate {
		t.Errorf("expected Intermediate default, got %s", got.Type)
	}
}

func TestGetAllProfiles_ReturnsCopy(t *testing.T) {
	f := NewFetcher(nil)

	modern := PredefinedProfiles[ProfileTypeModern]
	f.setProfile(ComponentAPIServer, &modern)

	old := PredefinedProfiles[ProfileTypeOld]
	f.setProfile(ComponentIngressController, &old)

	all := f.GetAllProfiles()
	if len(all) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(all))
	}
	if all[ComponentAPIServer].Type != ProfileTypeModern {
		t.Errorf("expected Modern for APIServer, got %s", all[ComponentAPIServer].Type)
	}
	if all[ComponentIngressController].Type != ProfileTypeOld {
		t.Errorf("expected Old for IngressController, got %s", all[ComponentIngressController].Type)
	}

	// Mutating returned map should not affect the fetcher
	delete(all, ComponentAPIServer)
	got := f.GetProfile(ComponentAPIServer)
	if got.Type != ProfileTypeModern {
		t.Error("deleting from GetAllProfiles result should not affect fetcher state")
	}
}

func TestSetAdherence_RoundTrip(t *testing.T) {
	f := NewFetcher(nil)

	if got := f.GetAdherence(); got != "" {
		t.Errorf("expected empty default, got %q", got)
	}

	f.setAdherence(AdherenceStrict)
	if got := f.GetAdherence(); got != AdherenceStrict {
		t.Errorf("expected %q, got %q", AdherenceStrict, got)
	}
}

func newInterceptedFetcherClient(getFunc func(ctx context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error,
	listFunc func(ctx context.Context, list *unstructured.UnstructuredList) error) client.Client {
	scheme := runtime.NewScheme()
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if u, ok := obj.(*unstructured.Unstructured); ok && getFunc != nil {
					return getFunc(ctx, key, u)
				}
				return c.Get(ctx, key, obj, opts...)
			},
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if u, ok := list.(*unstructured.UnstructuredList); ok && listFunc != nil {
					return listFunc(ctx, u)
				}
				return c.List(ctx, list, opts...)
			},
		}).
		Build()
}

func TestFetchAPIServerProfile_ModernProfile(t *testing.T) {
	cl := newInterceptedFetcherClient(
		func(_ context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
			if obj.GetKind() == "APIServer" && key.Name == "cluster" {
				obj.Object["spec"] = map[string]any{
					"tlsSecurityProfile": map[string]any{"type": "Modern"},
				}
				return nil
			}
			return fmt.Errorf("not found")
		}, nil)

	f := NewFetcher(cl)
	profile, _, err := f.fetchAPIServerProfile(context.Background())
	if err != nil {
		t.Fatalf("fetchAPIServerProfile() error = %v", err)
	}
	if profile.Type != ProfileTypeModern {
		t.Errorf("Type = %v, want Modern", profile.Type)
	}
	if profile.MinTLSVersion != VersionTLS13 {
		t.Errorf("MinTLSVersion = %v, want VersionTLS13", profile.MinTLSVersion)
	}
}

func TestFetchAPIServerProfile_CustomProfile(t *testing.T) {
	cl := newInterceptedFetcherClient(
		func(_ context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
			if obj.GetKind() == "APIServer" && key.Name == "cluster" {
				obj.Object["spec"] = map[string]any{
					"tlsSecurityProfile": map[string]any{
						"type": "Custom",
						"custom": map[string]any{
							"minTLSVersion": "VersionTLS12",
							"ciphers":       []any{"TLS_AES_128_GCM_SHA256"},
							"groups":        []any{"X25519"},
						},
					},
				}
				return nil
			}
			return fmt.Errorf("not found")
		}, nil)

	f := NewFetcher(cl)
	profile, _, err := f.fetchAPIServerProfile(context.Background())
	if err != nil {
		t.Fatalf("fetchAPIServerProfile() error = %v", err)
	}
	if profile.Type != ProfileTypeCustom {
		t.Errorf("Type = %v, want Custom", profile.Type)
	}
	if profile.MinTLSVersion != "VersionTLS12" {
		t.Errorf("MinTLSVersion = %v, want VersionTLS12", profile.MinTLSVersion)
	}
	if len(profile.Ciphers) != 1 || profile.Ciphers[0] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("Ciphers = %v, want [TLS_AES_128_GCM_SHA256]", profile.Ciphers)
	}
	if len(profile.Groups) != 1 || profile.Groups[0] != "X25519" {
		t.Errorf("Groups = %v, want [X25519]", profile.Groups)
	}
}

func TestFetchAPIServerProfile_Adherence(t *testing.T) {
	cl := newInterceptedFetcherClient(
		func(_ context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
			if obj.GetKind() == "APIServer" && key.Name == "cluster" {
				obj.Object["spec"] = map[string]any{
					"tlsSecurityProfile": map[string]any{"type": "Modern"},
					"tlsAdherence":       "StrictAllComponents",
				}
				return nil
			}
			return fmt.Errorf("not found")
		}, nil)

	f := NewFetcher(cl)
	_, adherence, err := f.fetchAPIServerProfile(context.Background())
	if err != nil {
		t.Fatalf("fetchAPIServerProfile() error = %v", err)
	}
	if adherence != AdherenceStrict {
		t.Errorf("adherence = %q, want %q", adherence, AdherenceStrict)
	}
}

func TestFetchIngressControllerProfile_Intermediate(t *testing.T) {
	cl := newInterceptedFetcherClient(
		func(_ context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
			if obj.GetKind() == "IngressController" && key.Name == "default" && key.Namespace == "openshift-ingress-operator" {
				obj.Object["spec"] = map[string]any{
					"tlsSecurityProfile": map[string]any{"type": "Intermediate"},
				}
				return nil
			}
			return fmt.Errorf("not found")
		}, nil)

	f := NewFetcher(cl)
	profile, err := f.fetchIngressControllerProfile(context.Background())
	if err != nil {
		t.Fatalf("fetchIngressControllerProfile() error = %v", err)
	}
	if profile.Type != ProfileTypeIntermediate {
		t.Errorf("Type = %v, want Intermediate", profile.Type)
	}
}

func TestFetchKubeletConfigProfile_WithTLSProfile(t *testing.T) {
	cl := newInterceptedFetcherClient(nil,
		func(_ context.Context, list *unstructured.UnstructuredList) error {
			if list.GetKind() == "KubeletConfigList" {
				list.Items = []unstructured.Unstructured{
					{Object: map[string]any{
						"apiVersion": "machineconfiguration.openshift.io/v1",
						"kind":       "KubeletConfig",
						"metadata":   map[string]any{"name": "kc-with-tls"},
						"spec": map[string]any{
							"tlsSecurityProfile": map[string]any{"type": "Old"},
						},
					}},
				}
				return nil
			}
			return fmt.Errorf("not found")
		})

	f := NewFetcher(cl)
	profile, err := f.fetchKubeletConfigProfile(context.Background())
	if err != nil {
		t.Fatalf("fetchKubeletConfigProfile() error = %v", err)
	}
	if profile.Type != ProfileTypeOld {
		t.Errorf("Type = %v, want Old", profile.Type)
	}
}

func TestFetchKubeletConfigProfile_NoneHaveTLS(t *testing.T) {
	cl := newInterceptedFetcherClient(nil,
		func(_ context.Context, list *unstructured.UnstructuredList) error {
			if list.GetKind() == "KubeletConfigList" {
				list.Items = []unstructured.Unstructured{
					{Object: map[string]any{
						"apiVersion": "machineconfiguration.openshift.io/v1",
						"kind":       "KubeletConfig",
						"metadata":   map[string]any{"name": "kc1"},
						"spec":       map[string]any{},
					}},
				}
				return nil
			}
			return fmt.Errorf("not found")
		})

	f := NewFetcher(cl)
	profile, err := f.fetchKubeletConfigProfile(context.Background())
	if err != nil {
		t.Fatalf("fetchKubeletConfigProfile() error = %v", err)
	}
	if profile.Type != ProfileTypeIntermediate {
		t.Errorf("Type = %v, want Intermediate (default)", profile.Type)
	}
}

func TestRefreshAll_SetsAllThreeProfiles(t *testing.T) {
	cl := newInterceptedFetcherClient(
		func(_ context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
			switch obj.GetKind() {
			case "APIServer":
				obj.Object["spec"] = map[string]any{
					"tlsSecurityProfile": map[string]any{"type": "Modern"},
					"tlsAdherence":       "StrictAllComponents",
				}
				return nil
			case "IngressController":
				obj.Object["spec"] = map[string]any{
					"tlsSecurityProfile": map[string]any{"type": "Old"},
				}
				return nil
			}
			return fmt.Errorf("not found")
		},
		func(_ context.Context, list *unstructured.UnstructuredList) error {
			if list.GetKind() == "KubeletConfigList" {
				list.Items = []unstructured.Unstructured{
					{Object: map[string]any{
						"apiVersion": "machineconfiguration.openshift.io/v1",
						"kind":       "KubeletConfig",
						"metadata":   map[string]any{"name": "kc1"},
						"spec": map[string]any{
							"tlsSecurityProfile": map[string]any{"type": "Intermediate"},
						},
					}},
				}
				return nil
			}
			return fmt.Errorf("not found")
		})

	f := NewFetcher(cl)
	f.RefreshAll(context.Background())

	if got := f.GetProfile(ComponentAPIServer); got.Type != ProfileTypeModern {
		t.Errorf("APIServer profile = %v, want Modern", got.Type)
	}
	if got := f.GetProfile(ComponentIngressController); got.Type != ProfileTypeOld {
		t.Errorf("IngressController profile = %v, want Old", got.Type)
	}
	if got := f.GetProfile(ComponentKubeletConfig); got.Type != ProfileTypeIntermediate {
		t.Errorf("KubeletConfig profile = %v, want Intermediate", got.Type)
	}
	if got := f.GetAdherence(); got != AdherenceStrict {
		t.Errorf("adherence = %q, want %q", got, AdherenceStrict)
	}
}

func TestRefreshAll_FallsBackToDefaultOnError(t *testing.T) {
	cl := newInterceptedFetcherClient(
		func(_ context.Context, _ client.ObjectKey, _ *unstructured.Unstructured) error {
			return fmt.Errorf("not found on non-OpenShift cluster")
		},
		func(_ context.Context, _ *unstructured.UnstructuredList) error {
			return fmt.Errorf("not found on non-OpenShift cluster")
		})

	f := NewFetcher(cl)
	f.RefreshAll(context.Background())

	for _, component := range []Component{ComponentAPIServer, ComponentIngressController, ComponentKubeletConfig} {
		got := f.GetProfile(component)
		if got.Type != ProfileTypeIntermediate {
			t.Errorf("%s profile = %v, want Intermediate (default)", component, got.Type)
		}
	}
	if got := f.GetAdherence(); got != "" {
		t.Errorf("adherence = %q, want empty on error fallback", got)
	}
}

func TestRefreshAll_FetchesInParallel(t *testing.T) {
	delay := 80 * time.Millisecond
	cl := newInterceptedFetcherClient(
		func(_ context.Context, _ client.ObjectKey, obj *unstructured.Unstructured) error {
			time.Sleep(delay)
			obj.Object["spec"] = map[string]any{
				"tlsSecurityProfile": map[string]any{"type": "Intermediate"},
			}
			return nil
		},
		func(_ context.Context, _ *unstructured.UnstructuredList) error {
			time.Sleep(delay)
			return nil
		})

	f := NewFetcher(cl)
	start := time.Now()
	f.RefreshAll(context.Background())
	elapsed := time.Since(start)

	// Sequential fetches would take ~3*delay; parallel should finish near one delay.
	if elapsed >= 2*delay {
		t.Fatalf("RefreshAll took %v; want < %v to confirm parallel fetches", elapsed, 2*delay)
	}
}

func TestRefreshAll_PartialErrorKeepsSuccessfulProfiles(t *testing.T) {
	cl := newInterceptedFetcherClient(
		func(_ context.Context, key client.ObjectKey, obj *unstructured.Unstructured) error {
			switch obj.GetKind() {
			case "APIServer":
				return fmt.Errorf("APIServer missing")
			case "IngressController":
				obj.Object["spec"] = map[string]any{
					"tlsSecurityProfile": map[string]any{"type": "Old"},
				}
				return nil
			}
			return fmt.Errorf("not found")
		},
		func(_ context.Context, list *unstructured.UnstructuredList) error {
			if list.GetKind() == "KubeletConfigList" {
				list.Items = []unstructured.Unstructured{
					{Object: map[string]any{
						"apiVersion": "machineconfiguration.openshift.io/v1",
						"kind":       "KubeletConfig",
						"metadata":   map[string]any{"name": "kc1"},
						"spec": map[string]any{
							"tlsSecurityProfile": map[string]any{"type": "Modern"},
						},
					}},
				}
				return nil
			}
			return fmt.Errorf("not found")
		})

	f := NewFetcher(cl)
	f.RefreshAll(context.Background())

	if got := f.GetProfile(ComponentAPIServer); got.Type != ProfileTypeIntermediate {
		t.Errorf("APIServer profile = %v, want Intermediate (default on error)", got.Type)
	}
	if got := f.GetProfile(ComponentIngressController); got.Type != ProfileTypeOld {
		t.Errorf("IngressController profile = %v, want Old", got.Type)
	}
	if got := f.GetProfile(ComponentKubeletConfig); got.Type != ProfileTypeModern {
		t.Errorf("KubeletConfig profile = %v, want Modern", got.Type)
	}
	if got := f.GetAdherence(); got != "" {
		t.Errorf("adherence = %q, want empty when APIServer fetch fails", got)
	}
}
