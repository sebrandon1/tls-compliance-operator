package tlsprofile

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Fetcher retrieves and caches OpenShift TLS security profiles from the cluster.
type Fetcher struct {
	client client.Client

	mu        sync.RWMutex
	profiles  map[Component]Profile
	adherence string
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

// RefreshAll fetches TLS security profiles from all three OpenShift components concurrently.
// A component whose fetch fails keeps its last successfully fetched profile; only a
// component that has never been fetched successfully falls back to the default.
func (f *Fetcher) RefreshAll(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("tlsprofile-fetcher")

	var failures atomic.Int32
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		profile, adherence, err := f.fetchAPIServerProfile(ctx)
		if err != nil {
			failures.Add(1)
			f.applyFetchFailure(logger, ComponentAPIServer, err)
			return
		}
		f.setAPIServer(&profile, adherence)
	}()

	go func() {
		defer wg.Done()
		if !f.refreshComponent(ctx, logger, ComponentIngressController, f.fetchIngressControllerProfile) {
			failures.Add(1)
		}
	}()

	go func() {
		defer wg.Done()
		if !f.refreshComponent(ctx, logger, ComponentKubeletConfig, f.fetchKubeletConfigProfile) {
			failures.Add(1)
		}
	}()

	wg.Wait()
	if n := failures.Load(); n > 0 {
		logger.Info("TLS security profile refresh incomplete", "failedComponents", n)
		return
	}
	logger.Info("TLS security profiles refreshed")
}

// refreshComponent fetches one component's profile and stores it. It reports
// whether the fetch succeeded.
func (f *Fetcher) refreshComponent(
	ctx context.Context, logger logr.Logger, component Component, fetch func(context.Context) (Profile, error),
) bool {
	profile, err := fetch(ctx)
	if err != nil {
		f.applyFetchFailure(logger, component, err)
		return false
	}
	f.setProfile(component, &profile)
	return true
}

// applyFetchFailure decides what to do when a fetch fails. A component that has
// a cached profile keeps it: a transient API error must not rewrite
// last-known-good data with defaults, which would silently flip compliance
// results. Only a component with no cached profile gets the default.
func (f *Fetcher) applyFetchFailure(logger logr.Logger, component Component, err error) {
	if f.hasCachedProfile(component) {
		logger.V(1).Info("could not fetch TLS profile, keeping last known value",
			"component", component, "error", err)
		return
	}

	logger.V(1).Info("could not fetch TLS profile, using default", "component", component, "error", err)
	profile := DefaultProfile()
	f.setProfile(component, &profile)
}

// hasCachedProfile reports whether a profile has been stored for the component.
func (f *Fetcher) hasCachedProfile(component Component) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.profiles[component]
	return ok
}

// StartPeriodicRefresh starts a goroutine that periodically refreshes profiles.
// The caller is responsible for one synchronous refresh before the first scan
// (see RefreshAll); this loop only re-fetches on each tick so it cannot race
// the start of scanning.
func (f *Fetcher) StartPeriodicRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		logger := log.FromContext(ctx).WithName("tlsprofile-refresh")
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

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

func (f *Fetcher) setProfile(component Component, profile *Profile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles[component] = *profile
}

// GetAdherence returns the cached TLS adherence mode from the APIServer config.
// Returns an empty string on non-OpenShift clusters or when the field is absent.
func (f *Fetcher) GetAdherence() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.adherence
}

func (f *Fetcher) setAdherence(adherence string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adherence = adherence
}

func (f *Fetcher) setAPIServer(profile *Profile, adherence string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles[ComponentAPIServer] = *profile
	f.adherence = adherence
}

// fetchAPIServerProfile reads the cluster APIServer config.
func (f *Fetcher) fetchAPIServerProfile(ctx context.Context) (Profile, string, error) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "config.openshift.io",
		Version: "v1",
		Kind:    "APIServer",
	})

	if err := f.client.Get(ctx, client.ObjectKey{Name: "cluster"}, obj); err != nil {
		return Profile{}, "", fmt.Errorf("failed to get APIServer: %w", err)
	}

	profile, err := extractProfileFromUnstructured(obj)
	adherence := extractAdherence(obj)
	return profile, adherence, err
}

func extractAdherence(obj *unstructured.Unstructured) string {
	spec, ok := obj.Object["spec"].(map[string]any)
	if !ok {
		return ""
	}
	adherence, _ := spec["tlsAdherence"].(string)
	return adherence
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

	if groups, ok := custom["groups"].([]any); ok {
		for _, g := range groups {
			if s, ok := g.(string); ok {
				profile.Groups = append(profile.Groups, s)
			}
		}
	}

	return profile, nil
}
