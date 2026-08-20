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
	"fmt"
	"html/template"
	"io"
	"strconv"
	"time"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

var htmlReportTmpl = template.Must(template.New("html").Parse(htmlReportSource))

const htmlReportSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TLS Compliance Report</title>
<style>
body { font-family: system-ui, sans-serif; margin: 1.5rem; color: #151515; background: #fff; }
h1 { font-size: 1.4rem; margin: 0 0 .5rem; }
.meta { color: #6a6e73; margin: 0 0 1rem; }
.summary { display: flex; flex-wrap: wrap; gap: .5rem; margin: 0 0 1rem; }
.pill { border-radius: 999px; padding: .2rem .7rem; font-size: .85rem; }
.ok { background: #3e8635; color: #fff; }
.warn { background: #f0ab00; color: #151515; }
.bad { background: #c9190b; color: #fff; }
.info { background: #f0f0f0; color: #151515; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { border-bottom: 1px solid #d2d2d2; padding: .4rem .55rem; text-align: left; }
th { background: #f0f0f0; }
</style>
</head>
<body>
<h1>TLS Compliance Report</h1>
<p class="meta">Generated {{.Generated}} · {{.Total}} endpoints · {{printf "%.0f" .CompliancePercent}}% compliant</p>
<div class="summary">
<span class="pill ok">Compliant {{.Compliant}}</span>
<span class="pill warn">Warning {{.Warning}}</span>
<span class="pill bad">Non-compliant {{.NonCompliant}}</span>
<span class="pill info">Expired certs {{.CertExpired}}</span>
</div>
<table>
<thead><tr>
<th>Host</th><th>Port</th><th>Source</th><th>Compliance</th><th>Grade</th><th>FS</th>
<th>TLS1.3</th><th>TLS1.2</th><th>TLS1.0</th><th>PQC</th><th>MLKEM</th><th>CertExpiry</th><th>Age</th>
</tr></thead>
<tbody>
{{range .Rows}}
<tr>
<td>{{.Host}}</td><td>{{.Port}}</td><td>{{.Source}}</td>
<td><span class="pill {{.ComplianceClass}}">{{.Compliance}}</span></td>
<td><span class="pill {{.GradeClass}}">{{.Grade}}</span></td>
<td>{{.FS}}</td><td>{{.TLS13}}</td><td>{{.TLS12}}</td><td>{{.TLS10}}</td>
<td>{{.PQC}}</td><td>{{.MLKEM}}</td><td>{{.CertExpiry}}</td><td>{{.Age}}</td>
</tr>
{{end}}
</tbody>
</table>
</body>
</html>
`

type htmlReportData struct {
	Generated         string
	Total             int
	CompliancePercent float64
	Compliant         int
	Warning           int
	NonCompliant      int
	CertExpired       int
	Rows              []htmlReportRow
}

type htmlReportRow struct {
	Host            string
	Port            string
	Source          string
	Compliance      string
	ComplianceClass string
	Grade           string
	GradeClass      string
	FS              string
	TLS13           string
	TLS12           string
	TLS10           string
	PQC             string
	MLKEM           string
	CertExpiry      string
	Age             string
}

// WriteHTML writes a self-contained HTML report (inline CSS) to w.
func WriteHTML(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	now := time.Now()
	summary := ComputeSummary(reports, now)
	data := htmlReportData{
		Generated:         now.UTC().Format(time.RFC3339),
		Total:             summary.Total,
		CompliancePercent: summary.CompliancePercent,
		Compliant:         summary.ByStatus[securityv1alpha1.ComplianceStatusCompliant],
		Warning:           summary.ByStatus[securityv1alpha1.ComplianceStatusWarning],
		NonCompliant:      summary.ByStatus[securityv1alpha1.ComplianceStatusNonCompliant] + summary.ByStatus[securityv1alpha1.ComplianceStatusNoTLS] + summary.ByStatus[securityv1alpha1.ComplianceStatusPlaintextHTTP],
		CertExpired:       summary.CertExpired,
		Rows:              make([]htmlReportRow, 0, len(reports)),
	}
	for i := range reports {
		data.Rows = append(data.Rows, reportToHTMLRow(&reports[i], now))
	}
	if err := htmlReportTmpl.Execute(w, &data); err != nil {
		return fmt.Errorf("encoding HTML: %w", err)
	}
	return nil
}

func reportToHTMLRow(r *securityv1alpha1.TLSComplianceReport, now time.Time) htmlReportRow {
	certExpiry, age := "", ""
	if r.Status.CertificateInfo != nil {
		certExpiry = strconv.Itoa(r.Status.CertificateInfo.DaysUntilExpiry)
	}
	if !r.CreationTimestamp.IsZero() {
		age = formatAge(now.Sub(r.CreationTimestamp.Time))
	}
	compliance := string(r.Status.ComplianceStatus)
	grade := r.Status.OverallCipherGrade
	return htmlReportRow{
		Host:            r.Spec.Host,
		Port:            strconv.Itoa(int(r.Spec.Port)),
		Source:          string(r.Spec.SourceKind),
		Compliance:      compliance,
		ComplianceClass: complianceHTMLClass(r.Status.ComplianceStatus),
		Grade:           grade,
		GradeClass:      gradeHTMLClass(grade),
		FS:              strconv.FormatBool(r.Status.ForwardSecrecy),
		TLS13:           strconv.FormatBool(r.Status.TLSVersions.TLS13),
		TLS12:           strconv.FormatBool(r.Status.TLSVersions.TLS12),
		TLS10:           strconv.FormatBool(r.Status.TLSVersions.TLS10),
		PQC:             string(r.Status.PQCReadiness),
		MLKEM:           strconv.FormatBool(r.Status.MLKEMSupported),
		CertExpiry:      certExpiry,
		Age:             age,
	}
}

func complianceHTMLClass(status securityv1alpha1.ComplianceStatus) string {
	switch status {
	case securityv1alpha1.ComplianceStatusCompliant:
		return "ok"
	case securityv1alpha1.ComplianceStatusWarning, securityv1alpha1.ComplianceStatusMutualTLSRequired:
		return "warn"
	case securityv1alpha1.ComplianceStatusNonCompliant, securityv1alpha1.ComplianceStatusNoTLS, securityv1alpha1.ComplianceStatusPlaintextHTTP:
		return "bad"
	default:
		return "info"
	}
}

func gradeHTMLClass(grade string) string {
	switch grade {
	case "A", "B":
		return "ok"
	case "C":
		return "warn"
	case "D", "F":
		return "bad"
	default:
		return "info"
	}
}
