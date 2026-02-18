package tlsprofile

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Fetcher retrieves and caches OpenShift TLS security profiles from the cluster.
type Fetcher struct {
	client client.Client

	mu       sync.RWMutex
	profiles map[Component]Profile
}

// NewFetcher creates a new profile Fetcher.
func NewFetcher(c client.Client) *Fetcher {
	return &Fetcher{
		client:   c,
		profiles: make(map[Component]Profile),
	}
}

// GetProfile returns the cached profile for the given component.
// Returns the default (Intermediate) profile if no profile has been fetched.
func (f *Fetcher) GetProfile(component Component) Profile {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if p, ok := f.profiles[component]; ok {
		return p
	}
	return DefaultProfile()
}

// GetAllProfiles returns a copy of all cached profiles.
func (f *Fetcher) GetAllProfiles() map[Component]Profile {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make(map[Component]Profile, len(f.profiles))
	maps.Copy(result, f.profiles)
	return result
}

// RefreshAll fetches TLS security profiles from all three OpenShift components.
func (f *Fetcher) RefreshAll(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("tlsprofile-fetcher")

	// Fetch APIServer profile
	profile, err := f.fetchAPIServerProfile(ctx)
	if err != nil {
		logger.V(1).Info("could not fetch APIServer TLS profile, using default", "error", err)
		profile = DefaultProfile()
	}
	f.setProfile(ComponentAPIServer, profile)

	// Fetch IngressController profile
	profile, err = f.fetchIngressControllerProfile(ctx)
	if err != nil {
		logger.V(1).Info("could not fetch IngressController TLS profile, using default", "error", err)
		profile = DefaultProfile()
	}
	f.setProfile(ComponentIngressController, profile)

	// Fetch KubeletConfig profile
	profile, err = f.fetchKubeletConfigProfile(ctx)
	if err != nil {
		logger.V(1).Info("could not fetch KubeletConfig TLS profile, using default", "error", err)
		profile = DefaultProfile()
	}
	f.setProfile(ComponentKubeletConfig, profile)

	logger.Info("TLS security profiles refreshed")
}

// StartPeriodicRefresh starts a goroutine that periodically refreshes profiles.
func (f *Fetcher) StartPeriodicRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		logger := log.FromContext(ctx).WithName("tlsprofile-refresh")
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Initial refresh
		f.RefreshAll(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logger.V(1).Info("refreshing TLS security profiles")
				f.RefreshAll(ctx)
			}
		}
	}()
}

func (f *Fetcher) setProfile(component Component, profile Profile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles[component] = profile
}

// fetchAPIServerProfile reads the cluster APIServer config.
func (f *Fetcher) fetchAPIServerProfile(ctx context.Context) (Profile, error) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "config.openshift.io",
		Version: "v1",
		Kind:    "APIServer",
	})

	if err := f.client.Get(ctx, client.ObjectKey{Name: "cluster"}, obj); err != nil {
		return Profile{}, fmt.Errorf("failed to get APIServer: %w", err)
	}

	return extractProfileFromUnstructured(obj)
}

// fetchIngressControllerProfile reads the default IngressController config.
func (f *Fetcher) fetchIngressControllerProfile(ctx context.Context) (Profile, error) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "operator.openshift.io",
		Version: "v1",
		Kind:    "IngressController",
	})

	if err := f.client.Get(ctx, client.ObjectKey{
		Namespace: "openshift-ingress-operator",
		Name:      "default",
	}, obj); err != nil {
		return Profile{}, fmt.Errorf("failed to get IngressController: %w", err)
	}

	return extractProfileFromUnstructured(obj)
}

// fetchKubeletConfigProfile reads the first KubeletConfig with a TLS profile.
func (f *Fetcher) fetchKubeletConfigProfile(ctx context.Context) (Profile, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "machineconfiguration.openshift.io",
		Version: "v1",
		Kind:    "KubeletConfigList",
	})

	if err := f.client.List(ctx, list); err != nil {
		return Profile{}, fmt.Errorf("failed to list KubeletConfigs: %w", err)
	}

	for i := range list.Items {
		profile, err := extractProfileFromUnstructured(&list.Items[i])
		if err == nil {
			return profile, nil
		}
	}

	// No KubeletConfig has a TLS profile set; use default.
	return DefaultProfile(), nil
}

// extractProfileFromUnstructured extracts a TLS security profile from an
// unstructured object's spec.tlsSecurityProfile field.
func extractProfileFromUnstructured(obj *unstructured.Unstructured) (Profile, error) {
	spec, ok := obj.Object["spec"].(map[string]any)
	if !ok {
		return Profile{}, fmt.Errorf("no spec found")
	}

	tlsProfile, ok := spec["tlsSecurityProfile"].(map[string]any)
	if !ok {
		// No TLS profile configured; the component uses the default.
		return DefaultProfile(), nil
	}

	profileType, _ := tlsProfile["type"].(string)

	switch ProfileType(profileType) {
	case ProfileTypeOld:
		return PredefinedProfiles[ProfileTypeOld], nil
	case ProfileTypeModern:
		return PredefinedProfiles[ProfileTypeModern], nil
	case ProfileTypeCustom:
		return extractCustomProfile(tlsProfile)
	default:
		// Intermediate is the default
		return PredefinedProfiles[ProfileTypeIntermediate], nil
	}
}

// extractCustomProfile extracts a custom TLS profile from unstructured data.
func extractCustomProfile(tlsProfile map[string]any) (Profile, error) {
	custom, ok := tlsProfile["custom"].(map[string]any)
	if !ok {
		return Profile{}, fmt.Errorf("custom profile type specified but no custom field found")
	}

	profile := Profile{
		Type: ProfileTypeCustom,
	}

	if minVersion, ok := custom["minTLSVersion"].(string); ok {
		profile.MinTLSVersion = TLSVersion(minVersion)
	}

	if ciphers, ok := custom["ciphers"].([]any); ok {
		for _, c := range ciphers {
			if s, ok := c.(string); ok {
				profile.Ciphers = append(profile.Ciphers, s)
			}
		}
	}

	return profile, nil
}
