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
	"errors"
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type paginationTestPage struct {
	items         []corev1.Pod
	continueToken string
	err           error
}

type paginationTestReader struct {
	pages []paginationTestPage
	calls []client.ListOptions
}

func (r *paginationTestReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("unexpected Get call")
}

func (r *paginationTestReader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	var listOpts client.ListOptions
	for _, opt := range opts {
		opt.ApplyToList(&listOpts)
	}
	r.calls = append(r.calls, listOpts)

	pageIndex := len(r.calls) - 1
	if pageIndex >= len(r.pages) {
		return fmt.Errorf("unexpected page request %d", pageIndex+1)
	}

	page := r.pages[pageIndex]
	if page.err != nil {
		return page.err
	}

	podList, ok := list.(*corev1.PodList)
	if !ok {
		return fmt.Errorf("unexpected list type %T", list)
	}

	// paginatedList reuses the list object, so replace the page contents rather
	// than appending to them. This also makes stale items visible to the test.
	podList.Items = append(podList.Items[:0], page.items...)
	podList.SetContinue(page.continueToken)
	return nil
}

func TestPaginatedList_SinglePage(t *testing.T) {
	reader := &paginationTestReader{
		pages: []paginationTestPage{{
			items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "first"}}},
		}},
	}
	var list corev1.PodList
	var callbackPages [][]string

	err := paginatedList(context.Background(), reader, &list, func() {
		var names []string
		for _, item := range list.Items {
			names = append(names, item.Name)
		}
		callbackPages = append(callbackPages, names)
	})

	if err != nil {
		t.Fatalf("paginatedList() error = %v", err)
	}
	if len(callbackPages) != 1 {
		t.Fatalf("callback count = %d, want 1", len(callbackPages))
	}
	if got, want := callbackPages[0], []string{"first"}; !reflect.DeepEqual(got, want) {
		t.Errorf("callback items = %v, want %v", got, want)
	}
	if len(reader.calls) != 1 {
		t.Fatalf("List call count = %d, want 1", len(reader.calls))
	}
	if got := reader.calls[0].Continue; got != "" {
		t.Errorf("initial Continue = %q, want empty", got)
	}
}

func TestPaginatedList_ForwardsOptionsAndContinueTokens(t *testing.T) {
	reader := &paginationTestReader{
		pages: []paginationTestPage{
			{
				items:         []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "first"}}},
				continueToken: "page-2",
			},
			{
				items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "second"}}},
			},
		},
	}
	var list corev1.PodList
	var callbackItems [][]string

	err := paginatedList(
		context.Background(),
		reader,
		&list,
		func() {
			var names []string
			for _, item := range list.Items {
				names = append(names, item.Name)
			}
			callbackItems = append(callbackItems, names)
		},
		client.InNamespace("team-a"),
		client.MatchingLabels{"app": "tls"},
	)

	if err != nil {
		t.Fatalf("paginatedList() error = %v", err)
	}
	if got, want := len(callbackItems), 2; got != want {
		t.Fatalf("callback count = %d, want %d", got, want)
	}
	if got, want := callbackItems, [][]string{{"first"}, {"second"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("callback items = %v, want %v", got, want)
	}
	if got, want := len(reader.calls), 2; got != want {
		t.Fatalf("List call count = %d, want %d", got, want)
	}

	for i, opts := range reader.calls {
		if got, want := opts.Limit, int64(listPageSize); got != want {
			t.Errorf("call %d Limit = %d, want %d", i+1, got, want)
		}
		if got, want := opts.Namespace, "team-a"; got != want {
			t.Errorf("call %d Namespace = %q, want %q", i+1, got, want)
		}
		if opts.LabelSelector == nil || !opts.LabelSelector.Matches(labels.Set{"app": "tls"}) {
			t.Errorf("call %d LabelSelector = %v, want app=tls", i+1, opts.LabelSelector)
		}
	}
	if got, want := reader.calls[0].Continue, ""; got != want {
		t.Errorf("first Continue = %q, want %q", got, want)
	}
	if got, want := reader.calls[1].Continue, "page-2"; got != want {
		t.Errorf("second Continue = %q, want %q", got, want)
	}
}

func TestPaginatedList_ReturnsFirstPageErrorWithoutCallback(t *testing.T) {
	wantErr := errors.New("first page failed")
	reader := &paginationTestReader{
		pages: []paginationTestPage{{err: wantErr}},
	}
	var list corev1.PodList
	callbackCount := 0

	err := paginatedList(context.Background(), reader, &list, func() {
		callbackCount++
	})

	if !errors.Is(err, wantErr) {
		t.Fatalf("paginatedList() error = %v, want %v", err, wantErr)
	}
	if callbackCount != 0 {
		t.Errorf("callback count = %d, want 0", callbackCount)
	}
	if len(reader.calls) != 1 {
		t.Errorf("List call count = %d, want 1", len(reader.calls))
	}
}

func TestPaginatedList_ReturnsLaterPageErrorAfterSuccessfulPages(t *testing.T) {
	wantErr := errors.New("second page failed")
	reader := &paginationTestReader{
		pages: []paginationTestPage{
			{
				items:         []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "first"}}},
				continueToken: "page-2",
			},
			{err: wantErr},
		},
	}
	var list corev1.PodList
	callbackCount := 0

	err := paginatedList(context.Background(), reader, &list, func() {
		callbackCount++
	})

	if !errors.Is(err, wantErr) {
		t.Fatalf("paginatedList() error = %v, want %v", err, wantErr)
	}
	if callbackCount != 1 {
		t.Errorf("callback count = %d, want 1", callbackCount)
	}
	if len(reader.calls) != 2 {
		t.Errorf("List call count = %d, want 2", len(reader.calls))
	}
}
