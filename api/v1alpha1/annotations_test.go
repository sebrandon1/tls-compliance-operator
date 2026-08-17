package v1alpha1

import "testing"

func TestRescanAnnotation_StableKey(t *testing.T) {
	// The plugin and controller share this key. Changing it would leave
	// existing annotated reports unscanned and break kubectl tlsreport rescan.
	const want = "tls-compliance.telco.openshift.io/rescan"
	if RescanAnnotation != want {
		t.Errorf("RescanAnnotation = %q, want %q", RescanAnnotation, want)
	}
}
