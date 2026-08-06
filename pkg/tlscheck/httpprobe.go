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

package tlscheck

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

var httpResponsePrefix = []byte("HTTP/")

// probeHTTP returns true if the endpoint serves plaintext HTTP.
// Called only after NoTLS classification to refine the diagnosis.
func (c *TLSChecker) probeHTTP(ctx context.Context, addr, host string) bool {
	dialer := &net.Dialer{Timeout: c.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	deadline := time.Now().Add(c.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	sanitizedHost := strings.NewReplacer("\r", "", "\n", "").Replace(host)
	request := fmt.Appendf(nil, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", sanitizedHost)
	if _, err := conn.Write(request); err != nil {
		return false
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	return bytes.HasPrefix(buf[:n], httpResponsePrefix)
}
