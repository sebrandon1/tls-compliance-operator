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
	"testing"
	"time"
)

func TestNewStaticFetcher_AppliesProfileToAllComponents(t *testing.T) {
	for _, profileType := range []ProfileType{ProfileTypeOld, ProfileTypeIntermediate, ProfileTypeModern} {
		t.Run(string(profileType), func(t *testing.T) {
			f, err := NewStaticFetcher(profileType)
			if err != nil {
				t.Fatalf("NewStaticFetcher(%q) error = %v", profileType, err)
			}
			if got := f.GetSource(); got != SourceOverride {
				t.Errorf("GetSource() = %q, want %q", got, SourceOverride)
			}

			want := PredefinedProfiles[profileType]
			for _, component := range []Component{
				ComponentAPIServer,
				ComponentIngressController,
				ComponentKubeletConfig,
			} {
				got := f.GetProfile(component)
				if got.Type != want.Type || got.MinTLSVersion != want.MinTLSVersion {
					t.Errorf("%s profile = %+v, want %+v", component, got, want)
				}
			}
		})
	}
}

func TestNewStaticFetcher_RejectsInvalidTypes(t *testing.T) {
	for _, profileType := range []ProfileType{ProfileTypeCustom, "", "bogus", "old"} {
		t.Run(string(profileType), func(t *testing.T) {
			if _, err := NewStaticFetcher(profileType); err == nil {
				t.Fatalf("NewStaticFetcher(%q) error = nil, want error", profileType)
			}
		})
	}
}

func TestStaticFetcher_NeverTouchesTheCluster(t *testing.T) {
	// A nil client would panic if the static fetcher ever issued a request.
	f, err := NewStaticFetcher(ProfileTypeModern)
	if err != nil {
		t.Fatalf("NewStaticFetcher() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Both must return immediately without dereferencing the client or
	// starting a goroutine that would race the test.
	f.RefreshAll(ctx)
	f.StartPeriodicRefresh(ctx, time.Millisecond)

	if got := f.GetProfile(ComponentAPIServer).Type; got != ProfileTypeModern {
		t.Errorf("profile changed after refresh calls: got %q, want Modern", got)
	}
}

func TestGetSource_ZeroValueFetcherDefaultsToCluster(t *testing.T) {
	f := &Fetcher{}
	if got := f.GetSource(); got != SourceCluster {
		t.Errorf("GetSource() = %q, want %q", got, SourceCluster)
	}
}

func TestNewFetcher_SourceDefaultsToCluster(t *testing.T) {
	f := NewFetcher(nil)
	if got := f.GetSource(); got != SourceCluster {
		t.Errorf("GetSource() = %q, want %q", got, SourceCluster)
	}
}

func TestValidateProfileType(t *testing.T) {
	for _, valid := range []string{"Old", "Intermediate", "Modern"} {
		if err := ValidateProfileType(valid); err != nil {
			t.Errorf("ValidateProfileType(%q) error = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"", "Custom", "old", "intermediate", "bogus"} {
		if err := ValidateProfileType(invalid); err == nil {
			t.Errorf("ValidateProfileType(%q) error = nil, want error", invalid)
		}
	}
}
