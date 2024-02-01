// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package podsecuritypolicy

import (
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/ptr"
)

// NewBasePolicy creates the base pod security policy with the minimal required permissions to be overridden if
// necessary.
func NewBasePolicy(name string) *policyv1beta1.PodSecurityPolicy {
	// This PodSecurityPolicy is equivalent to a "restricted" pod security standard,
	// according to: https://kubernetes.io/docs/reference/access-authn-authz/psp-to-pod-security-standards/
	return &policyv1beta1.PodSecurityPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"seccomp.security.alpha.kubernetes.io/allowedProfileNames": "*",
			},
			Name: name,
		},
		Spec: policyv1beta1.PodSecurityPolicySpec{
			Privileged:               false,
			AllowPrivilegeEscalation: ptr.BoolToPtr(false),
			RequiredDropCapabilities: []corev1.Capability{"ALL"},
			Volumes: []policyv1beta1.FSType{
				policyv1beta1.ConfigMap,
				policyv1beta1.DownwardAPI,
				policyv1beta1.EmptyDir,
				policyv1beta1.PersistentVolumeClaim,
				policyv1beta1.Projected,
				policyv1beta1.Secret,
			},
			HostPorts: []policyv1beta1.HostPortRange{{
				Min: int32(0),
				Max: int32(65535),
			}},
			HostNetwork: false,
			HostIPC:     false,
			HostPID:     false,
			RunAsUser: policyv1beta1.RunAsUserStrategyOptions{
				Rule: policyv1beta1.RunAsUserStrategyMustRunAsNonRoot,
			},
			SELinux: policyv1beta1.SELinuxStrategyOptions{
				Rule: policyv1beta1.SELinuxStrategyRunAsAny,
			},
			SupplementalGroups: policyv1beta1.SupplementalGroupsStrategyOptions{
				Rule: policyv1beta1.SupplementalGroupsStrategyMustRunAs,
				Ranges: []policyv1beta1.IDRange{
					{
						Min: int64(1),
						Max: int64(65535),
					},
				},
			},
			FSGroup: policyv1beta1.FSGroupStrategyOptions{
				Rule: policyv1beta1.FSGroupStrategyMustRunAs,
				Ranges: []policyv1beta1.IDRange{
					{
						Min: int64(1),
						Max: int64(65535),
					},
				},
			},
			ReadOnlyRootFilesystem: false,
		},
	}
}
