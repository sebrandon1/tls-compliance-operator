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
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecProcNetReader reads /proc/net/tcp and /proc/net/tcp6 from a pod
// container with the pods/exec subresource.
type ExecProcNetReader struct {
	// Config is the cluster REST configuration used to exec into pods.
	Config *rest.Config
}

// ReadProcNet returns the concatenated /proc/net/tcp and /proc/net/tcp6
// contents from the named container.
func (e *ExecProcNetReader) ReadProcNet(ctx context.Context, namespace, pod, container string) (string, error) {
	if e.Config == nil {
		return "", fmt.Errorf("no REST config configured")
	}
	clientset, err := kubernetes.NewForConfig(e.Config)
	if err != nil {
		return "", fmt.Errorf("build clientset: %w", err)
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(pod).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   []string{"cat", "/proc/net/tcp", "/proc/net/tcp6"},
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(e.Config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
		return "", fmt.Errorf("exec cat /proc/net/tcp: %w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}
