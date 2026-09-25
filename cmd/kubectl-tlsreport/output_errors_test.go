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

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func executeWithFailure(t *testing.T, cmd *cobra.Command, args []string, out, errOut io.Writer) error {
	t.Helper()
	cmd.SetArgs(args)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	return cmd.Execute()
}

type failOnceWriter struct {
	err   error
	wrote bool
}

func (w *failOnceWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
		return 0, w.err
	}
	return len(p), nil
}

func TestCommandOutputErrorsPropagate(t *testing.T) {
	originalFilterOpts, originalSortBy, originalOutputFormat := filterOpts, sortBy, outputFormat
	originalTargetOutputFormat, originalRawExport := targetOutputFormat, rawExport
	originalFailOnNonCompliant := failOnNonCompliant
	t.Cleanup(func() {
		filterOpts, sortBy, outputFormat = originalFilterOpts, originalSortBy, originalOutputFormat
		targetOutputFormat, rawExport = originalTargetOutputFormat, originalRawExport
		failOnNonCompliant = originalFailOnNonCompliant
	})

	t.Run("export", func(t *testing.T) {
		useFakeCommandClient(t, commandReport())
		filterOpts = export.FilterOptions{}
		sortBy = ""
		rawExport = false

		wantErr := errors.New("export write failed")
		err := executeWithFailure(t, newRootCmd(), []string{"json"}, failingWriter{err: wantErr}, io.Discard)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("summary", func(t *testing.T) {
		useFakeCommandClient(t, commandReport())
		filterOpts = export.FilterOptions{}
		sortBy = ""
		failOnNonCompliant = false

		wantErr := errors.New("summary write failed")
		err := executeWithFailure(t, newRootCmd(), []string{"summary"}, failingWriter{err: wantErr}, io.Discard)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("report describe", func(t *testing.T) {
		useFakeCommandClient(t, commandReport())
		wantErr := errors.New("describe write failed")
		err := executeWithFailure(t, newRootCmd(), []string{"describe", "report-1"}, failingWriter{err: wantErr}, io.Discard)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("table flush", func(t *testing.T) {
		useFakeCommandClient(t, commandReport())
		outputFormat = "table"
		filterOpts = export.FilterOptions{}
		sortBy = ""

		wantErr := errors.New("table flush failed")
		err := executeWithFailure(t, newRootCmd(), []string{"get"}, failingWriter{err: wantErr}, io.Discard)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("no match diagnostic", func(t *testing.T) {
		useFakeCommandClient(t)
		filterOpts = export.FilterOptions{}
		sortBy = ""

		wantErr := errors.New("diagnostic write failed")
		err := executeWithFailure(t, newRootCmd(), []string{"summary"}, io.Discard, failingWriter{err: wantErr})
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("rescan trigger diagnostic", func(t *testing.T) {
		report := commandReport()
		c := useFakeCommandClient(t, report)
		wantErr := errors.New("rescan diagnostic write failed")

		err := executeWithFailure(t, newRescanCmd(), []string{"report-1"}, io.Discard, failingWriter{err: wantErr})
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
		var updated securityv1alpha1.TLSComplianceReport
		if err := c.Get(context.Background(), client.ObjectKey{Name: report.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Annotations[securityv1alpha1.RescanAnnotation] == "" {
			t.Fatal("rescan annotation was not persisted before the output error")
		}
	})

	t.Run("target create diagnostic", func(t *testing.T) {
		c := useFakeCommandClient(t)
		wantErr := errors.New("target create diagnostic write failed")
		err := executeWithFailure(t, newTargetCreateCmd(), []string{"create.example.com", "443"}, io.Discard, failingWriter{err: wantErr})
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
		var target securityv1alpha1.TLSComplianceTarget
		if err := c.Get(context.Background(), client.ObjectKey{Name: "create-example-com-443"}, &target); err != nil {
			t.Fatalf("target was not created before its output error: %v", err)
		}
	})

	t.Run("target table flush", func(t *testing.T) {
		target := &securityv1alpha1.TLSComplianceTarget{
			ObjectMeta: metav1.ObjectMeta{Name: "target-1"},
			Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "example.com", Port: int32Pointer(443)},
		}
		useFakeCommandClient(t, target)
		targetOutputFormat = "table"

		wantErr := errors.New("target table flush failed")
		err := executeWithFailure(t, newTargetListCmd(), nil, failingWriter{err: wantErr}, io.Discard)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("rescan progress", func(t *testing.T) {
		report := commandReport()
		c := useFakeCommandClient(t, report)
		wantErr := errors.New("progress write failed")
		completed, err := waitForRescans(context.Background(), c, []string{report.Name}, 0, failingWriter{err: wantErr})
		if completed != 1 {
			t.Fatalf("completed = %d, want 1", completed)
		}
		if !errors.Is(err, wantErr) {
			t.Fatalf("waitForRescans() error = %v, want %v", err, wantErr)
		}

		transientErr := errors.New("transient progress write failed")
		completed, err = waitForRescans(context.Background(), c, []string{report.Name}, 0, &failOnceWriter{err: transientErr})
		if completed != 1 {
			t.Fatalf("waitForRescans() completion count = %d, want 1", completed)
		}
		if !errors.Is(err, transientErr) {
			t.Fatalf("waitForRescans() error = %v, want %v", err, transientErr)
		}
	})

	t.Run("version", func(t *testing.T) {
		wantErr := errors.New("version write failed")
		err := executeWithFailure(t, newRootCmd(), []string{"version"}, failingWriter{err: wantErr}, io.Discard)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("completion", func(t *testing.T) {
		wantErr := errors.New("completion write failed")
		err := executeWithFailure(t, newRootCmd(), []string{"completion", "bash"}, failingWriter{err: wantErr}, io.Discard)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
	})
}

func TestTargetUpdateAndDeleteOutputErrorsPropagate(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		target := &securityv1alpha1.TLSComplianceTarget{
			ObjectMeta: metav1.ObjectMeta{Name: "target-1"},
			Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "example.com", Port: int32Pointer(443)},
		}
		c := useFakeCommandClient(t, target)
		wantErr := errors.New("target update diagnostic write failed")
		err := executeWithFailure(t, newTargetUpdateCmd(), []string{"target-1", "--host", "updated.example.com"}, io.Discard, failingWriter{err: wantErr})
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
		var updated securityv1alpha1.TLSComplianceTarget
		if err := c.Get(context.Background(), client.ObjectKey{Name: target.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Spec.Host != "updated.example.com" {
			t.Fatalf("host = %q, want updated.example.com", updated.Spec.Host)
		}
	})

	t.Run("delete", func(t *testing.T) {
		target := &securityv1alpha1.TLSComplianceTarget{ObjectMeta: metav1.ObjectMeta{Name: "target-1"}}
		c := useFakeCommandClient(t, target)
		wantErr := errors.New("target delete diagnostic write failed")
		err := executeWithFailure(t, newTargetDeleteCmd(), []string{"target-1"}, io.Discard, failingWriter{err: wantErr})
		if !errors.Is(err, wantErr) {
			t.Fatalf("Execute() error = %v, want %v", err, wantErr)
		}
		var deleted securityv1alpha1.TLSComplianceTarget
		if err := c.Get(context.Background(), client.ObjectKey{Name: target.Name}, &deleted); err == nil {
			t.Fatal("target still exists after delete output failed")
		}
	})
}

func TestDiffOutputErrorPropagates(t *testing.T) {
	originalFilterOpts := filterOpts
	t.Cleanup(func() { filterOpts = originalFilterOpts })
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	filterOpts = export.FilterOptions{}
	wantErr := errors.New("diff output failed")
	err := executeWithFailure(t, newRootCmd(), []string{"diff", path, path, "-o", "json"}, failingWriter{err: wantErr}, io.Discard)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Execute() error = %v, want %v", err, wantErr)
	}
}
