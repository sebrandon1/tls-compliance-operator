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

package policy

import (
	"sync"
	"testing"
)

func TestStore_EmptyMatchesDefault(t *testing.T) {
	for name, store := range map[string]*Store{
		"nil store":  nil,
		"nil policy": NewStore(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if got := store.Match(Target{Namespace: "prod"}); got != DefaultProfile {
				t.Errorf("Match() = %q, want %q", got, DefaultProfile)
			}
			if got := store.Get(); got != nil {
				t.Errorf("Get() = %v, want nil", got)
			}
		})
	}
}

func TestStore_SetSwapsPolicy(t *testing.T) {
	store := NewStore(mustCompile(t, "rules:\n  - namespace: prod\n    profile: exempt\n").Policy)
	if got := store.Match(Target{Namespace: "prod"}); got != ProfileExempt {
		t.Fatalf("Match() before swap = %q, want exempt", got)
	}

	store.Set(mustCompile(t, "rules:\n  - namespace: prod\n    profile: kubelet\n").Policy)
	if got := store.Match(Target{Namespace: "prod"}); got != ProfileKubelet {
		t.Errorf("Match() after swap = %q, want kubelet", got)
	}
	if got := store.Match(Target{Namespace: "dev"}); got != DefaultProfile {
		t.Errorf("Match() for unmatched target = %q, want default", got)
	}

	store.Set(nil)
	if got := store.Match(Target{Namespace: "prod"}); got != DefaultProfile {
		t.Errorf("Match() after clearing = %q, want default", got)
	}
}

func TestStore_ConcurrentSetAndMatch(t *testing.T) {
	exempt := mustCompile(t, "rules:\n  - namespace: prod\n    profile: exempt\n").Policy
	kubelet := mustCompile(t, "rules:\n  - namespace: prod\n    profile: kubelet\n").Policy
	store := NewStore(exempt)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				store.Set(kubelet)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = store.Match(Target{Namespace: "prod"})
			}
		}()
	}
	wg.Wait()
}
