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

package v1alpha1

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	targetClient   client.Reader
	targetClientMu sync.RWMutex
)

// SetupTLSComplianceTargetWebhookWithManager registers the validating webhook.
func SetupTLSComplianceTargetWebhookWithManager(mgr ctrl.Manager) error {
	targetClientMu.Lock()
	targetClient = mgr.GetClient()
	targetClientMu.Unlock()
	return builder.WebhookManagedBy(mgr, &TLSComplianceTarget{}).
		WithValidator(&TLSComplianceTargetValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-security-telco-openshift-io-v1alpha1-tlscompliancetarget,mutating=false,failurePolicy=fail,sideEffects=None,groups=security.telco.openshift.io,resources=tlscompliancetargets,verbs=create;update,versions=v1alpha1,name=vtlscompliancetarget.kb.io,admissionReviewVersions=v1

// TLSComplianceTargetValidator validates TLSComplianceTarget resources.
type TLSComplianceTargetValidator struct{}

func (v *TLSComplianceTargetValidator) ValidateCreate(ctx context.Context, target *TLSComplianceTarget) (admission.Warnings, error) {
	allErrs := validateTargetSpec(target)
	if err := validateNoDuplicate(ctx, target, ""); err != nil {
		allErrs = append(allErrs, err)
	}
	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "TLSComplianceTarget"},
			target.Name, allErrs)
	}
	return nil, nil
}

func (v *TLSComplianceTargetValidator) ValidateUpdate(ctx context.Context, _, newTarget *TLSComplianceTarget) (admission.Warnings, error) {
	allErrs := validateTargetSpec(newTarget)
	if err := validateNoDuplicate(ctx, newTarget, newTarget.Name); err != nil {
		allErrs = append(allErrs, err)
	}
	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "TLSComplianceTarget"},
			newTarget.Name, allErrs)
	}
	return nil, nil
}

func (v *TLSComplianceTargetValidator) ValidateDelete(_ context.Context, _ *TLSComplianceTarget) (admission.Warnings, error) {
	return nil, nil
}

// reservedCIDRs lists IP ranges that must not be used as scan targets.
var reservedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"::1/128",        // IPv6 loopback
		"169.254.0.0/16", // IPv4 link-local (includes cloud metadata 169.254.169.254)
		"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"fc00::/7",       // IPv6 unique local
		"0.0.0.0/8",      // unspecified
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	return nets
}()

// internalHostSuffixes lists DNS suffixes that resolve to cluster-internal or
// infrastructure-internal endpoints.
var internalHostSuffixes = []string{
	".localhost",
	".svc.cluster.local",
}

// internalHostExact lists hostnames that must be blocked exactly.
var internalHostExact = []string{
	"localhost",
	"metadata.google.internal",
}

func validateTargetSpec(target *TLSComplianceTarget) field.ErrorList {
	var allErrs field.ErrorList
	specPath := field.NewPath("spec")
	host := target.Spec.Host
	if strings.Contains(host, "*") {
		allErrs = append(allErrs, field.Invalid(specPath.Child("host"), host, "wildcards are not allowed"))
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := validateIPNotReserved(specPath.Child("host"), ip, host); err != nil {
			allErrs = append(allErrs, err)
		}
	} else {
		if errs := validation.IsDNS1123Subdomain(host); len(errs) > 0 {
			allErrs = append(allErrs, field.Invalid(specPath.Child("host"), host,
				fmt.Sprintf("must be a valid IP address or DNS name: %s", strings.Join(errs, "; "))))
		}
		if err := validateHostnameNotInternal(specPath.Child("host"), host); err != nil {
			allErrs = append(allErrs, err)
		}
	}
	return allErrs
}

func validateIPNotReserved(fld *field.Path, ip net.IP, raw string) *field.Error {
	for _, cidr := range reservedCIDRs {
		if cidr.Contains(ip) {
			return field.Invalid(fld, raw,
				fmt.Sprintf("internal or reserved address (%s) is not allowed", cidr))
		}
	}
	return nil
}

func validateHostnameNotInternal(fld *field.Path, host string) *field.Error {
	lower := strings.ToLower(host)
	for _, exact := range internalHostExact {
		if lower == exact {
			return field.Invalid(fld, host, fmt.Sprintf("%q is not allowed", exact))
		}
	}
	for _, suffix := range internalHostSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return field.Invalid(fld, host, fmt.Sprintf("internal hostname (suffix %q) is not allowed", suffix))
		}
	}
	return nil
}

func validateNoDuplicate(ctx context.Context, target *TLSComplianceTarget, selfName string) *field.Error {
	targetClientMu.RLock()
	cl := targetClient
	targetClientMu.RUnlock()
	if cl == nil {
		return nil
	}
	var list TLSComplianceTargetList
	if err := cl.List(ctx, &list); err != nil {
		return nil
	}
	for i := range list.Items {
		existing := &list.Items[i]
		if existing.Name == selfName {
			continue
		}
		if existing.Spec.Host == target.Spec.Host && existing.Spec.Port == target.Spec.Port {
			return field.Invalid(field.NewPath("spec"),
				fmt.Sprintf("%s:%d", target.Spec.Host, target.Spec.Port),
				fmt.Sprintf("duplicate host:port — already defined in TLSComplianceTarget %q", existing.Name))
		}
	}
	return nil
}
