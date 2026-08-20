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

package export

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1/schema/sarif-schema-2.1.0.json"

const (
	sarifRuleNonCompliant  = "tls-non-compliant"
	sarifRuleNoTLS         = "tls-no-tls"
	sarifRulePlaintextHTTP = "tls-plaintext-http"
	sarifRuleWarning       = "tls-warning"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	FullDescription  sarifMessage `json:"fullDescription"`
	DefaultConfig    sarifConfig  `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

var sarifRules = []sarifRule{
	{
		ID:               sarifRuleNonCompliant,
		ShortDescription: sarifMessage{Text: "Endpoint supports only legacy TLS"},
		FullDescription:  sarifMessage{Text: "The endpoint does not support TLS 1.2 or TLS 1.3."},
		DefaultConfig:    sarifConfig{Level: "error"},
	},
	{
		ID:               sarifRuleNoTLS,
		ShortDescription: sarifMessage{Text: "Endpoint does not offer TLS"},
		FullDescription:  sarifMessage{Text: "The endpoint accepted a connection but did not negotiate TLS."},
		DefaultConfig:    sarifConfig{Level: "error"},
	},
	{
		ID:               sarifRulePlaintextHTTP,
		ShortDescription: sarifMessage{Text: "Endpoint serves plaintext HTTP"},
		FullDescription:  sarifMessage{Text: "The endpoint responded with plaintext HTTP instead of TLS."},
		DefaultConfig:    sarifConfig{Level: "error"},
	},
	{
		ID:               sarifRuleWarning,
		ShortDescription: sarifMessage{Text: "Endpoint supports modern TLS alongside legacy versions"},
		FullDescription:  sarifMessage{Text: "The endpoint supports TLS 1.2 or 1.3 but also accepts TLS 1.0, TLS 1.1, or SSL 3.0."},
		DefaultConfig:    sarifConfig{Level: "warning"},
	},
}

// WriteSARIF writes TLSComplianceReport items as a SARIF 2.1.0 log for GitHub Code Scanning.
func WriteSARIF(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	results := make([]sarifResult, 0)
	for i := range reports {
		if result, ok := reportToSARIFResult(&reports[i]); ok {
			results = append(results, result)
		}
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "tls-compliance-operator",
				InformationURI: "https://github.com/sebrandon1/tls-compliance-operator",
				Rules:          sarifRules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&log); err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}
	return nil
}

func reportToSARIFResult(r *securityv1alpha1.TLSComplianceReport) (sarifResult, bool) {
	ruleID, level, ok := sarifRuleForStatus(r.Status.ComplianceStatus)
	if !ok {
		return sarifResult{}, false
	}

	endpoint := net.JoinHostPort(r.Spec.Host, strconv.Itoa(int(r.Spec.Port)))
	return sarifResult{
		RuleID:  ruleID,
		Level:   level,
		Message: sarifMessage{Text: fmt.Sprintf("%s is %s", endpoint, r.Status.ComplianceStatus)},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: "tls://" + endpoint},
			},
		}},
	}, true
}

func sarifRuleForStatus(status securityv1alpha1.ComplianceStatus) (ruleID, level string, ok bool) {
	switch status {
	case securityv1alpha1.ComplianceStatusNonCompliant:
		return sarifRuleNonCompliant, "error", true
	case securityv1alpha1.ComplianceStatusNoTLS:
		return sarifRuleNoTLS, "error", true
	case securityv1alpha1.ComplianceStatusPlaintextHTTP:
		return sarifRulePlaintextHTTP, "error", true
	case securityv1alpha1.ComplianceStatusWarning:
		return sarifRuleWarning, "warning", true
	default:
		return "", "", false
	}
}
