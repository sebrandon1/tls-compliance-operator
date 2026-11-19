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

import "sync/atomic"

// Store holds the in-force policy so a ConfigMap update can swap it without
// restarting the operator. A compiled Policy is immutable, so readers take a
// pointer and use it for the whole reconcile while a writer swaps in a new one.
type Store struct {
	current atomic.Pointer[Policy]
}

// NewStore returns a Store holding p. A nil p leaves the store empty, which
// behaves like a policy with no rules.
func NewStore(p *Policy) *Store {
	s := &Store{}
	s.Set(p)
	return s
}

// Set replaces the in-force policy. A nil p clears it.
func (s *Store) Set(p *Policy) {
	if s == nil {
		return
	}
	s.current.Store(p)
}

// Get returns the in-force policy, or nil when the store is empty.
func (s *Store) Get() *Policy {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

// Match returns the profile selected for target. An empty store falls back to
// DefaultProfile, matching a nil *Policy.
func (s *Store) Match(target Target) Profile {
	return s.Get().Match(target)
}
