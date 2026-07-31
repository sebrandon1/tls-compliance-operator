//go:build parity

package parity

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestParity(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS Tool Parity Suite")
}
