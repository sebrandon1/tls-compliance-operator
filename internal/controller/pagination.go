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

package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// paginatedList iterates over all pages of a Kubernetes list call, invoking fn
// for each page. The list object is reused across pages. Extra list options
// (e.g. namespace, label selector) are forwarded to every API call.
func paginatedList(ctx context.Context, reader client.Reader, list client.ObjectList, fn func(), opts ...client.ListOption) error { //nolint:unparam // opts enables callers to pass namespace/label filters
	var continueToken string
	for {
		allOpts := make([]client.ListOption, 0, len(opts)+2)
		allOpts = append(allOpts, opts...)
		allOpts = append(allOpts, client.Limit(listPageSize), client.Continue(continueToken))

		if err := reader.List(ctx, list, allOpts...); err != nil {
			return err
		}

		fn()

		continueToken = list.GetContinue()
		if continueToken == "" {
			return nil
		}
	}
}
