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

import "testing"

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
