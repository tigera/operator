// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package util

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tigera/operator/pkg/types"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
)

const (
	Optional                   = true
	DefaultCertificateDuration = 100 * 365 * 24 * time.Hour

	OSTypeAny     OSType = "any"
	OSTypeLinux   OSType = "linux"
	OSTypeWindows OSType = "windows"

	// The name prefix used for the CA issuer, which is used for self-signed
	// certificates issued for operator-managed certificates.
	// NOTE: Do not change this field since we use this value to identify
	// certificates managed by this operator.
	TigeraOperatorCAIssuerPrefix = "tigera-operator-signer"
)

var (
	// TolerateMaster allows pod to be scheduled on master nodes
	TolerateMaster = corev1.Toleration{
		Key:    "node-role.kubernetes.io/master",
		Effect: corev1.TaintEffectNoSchedule,
	}

	// TolerateCriticalAddonsOnly allows pods to be rescheduled while the node is in "critical add-ons only" mode.
	TolerateCriticalAddonsOnly = corev1.Toleration{
		Key:      "CriticalAddonsOnly",
		Operator: corev1.TolerationOpExists,
	}
)

// TolerateAll returns tolerations to tolerate all taints. When used, it is not necessary
// to include the user's custom tolerations because we already tolerate everything.
var TolerateAll = []corev1.Toleration{
	TolerateCriticalAddonsOnly,
	{
		Effect:   corev1.TaintEffectNoSchedule,
		Operator: corev1.TolerationOpExists,
	},
	{
		Effect:   corev1.TaintEffectNoExecute,
		Operator: corev1.TolerationOpExists,
	},
}

// This type helps ensure that we only use defined os types
type OSType string

var log = logf.Log.WithName("render")

func SetTestLogger(l logr.Logger) {
	log = l
}

// envVarSourceFromConfigmap returns an EnvVarSource using the given configmap name and configmap key.
func envVarSourceFromConfigmap(configmapName, key string) *v1.EnvVarSource {
	return &v1.EnvVarSource{
		ConfigMapKeyRef: &v1.ConfigMapKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: configmapName,
			},
			Key: key,
		},
	}
}

// EnvVarSourceFromSecret returns an EnvVarSource using the given secret name and key.
func EnvVarSourceFromSecret(secretName, key string, optional bool) *v1.EnvVarSource {
	var opt *bool
	if optional {
		real := optional
		opt = &real
	}
	return &v1.EnvVarSource{
		SecretKeyRef: &v1.SecretKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: secretName,
			},
			Key:      key,
			Optional: opt,
		},
	}
}

//type CertificateExtensionFunc func(*x509.Certificate) error
func SetClientAuth(x *x509.Certificate) error {
	if x.ExtKeyUsage == nil {
		x.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	x.ExtKeyUsage = append(x.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	return nil
}
func SetServerAuth(x *x509.Certificate) error {
	if x.ExtKeyUsage == nil {
		x.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	x.ExtKeyUsage = append(x.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	return nil
}

// ParseEndpoint parses an endpoint of the form scheme://host:port and returns the components.
func ParseEndpoint(endpoint string) (string, string, string, error) {
	url, err := url.Parse(endpoint)
	if err != nil {
		return "", "", "", err
	}
	splits := strings.Split(url.Host, ":")
	if len(splits) != 2 {
		return "", "", "", fmt.Errorf("Invalid host: %s", url.Host)
	}
	return url.Scheme, splits[0], splits[1], nil
}

func ParseHostPort(hostport string) (string, string, error) {
	splits := strings.Split(hostport, ":")
	if len(splits) != 2 {
		return "", "", fmt.Errorf("Invalid HostPort: %s", hostport)
	}
	return splits[0], splits[1], nil

}

func GetImagePullSecretReferenceList(pullSecrets []*v1.Secret) []v1.LocalObjectReference {
	var ps []v1.LocalObjectReference
	for _, x := range pullSecrets {
		ps = append(ps, v1.LocalObjectReference{Name: x.Name})
	}
	return ps
}

// GetResourceRequirements retrieves the component ResourcesRequirements from the installation
// If it doesn't exist, it returns an empty ResourceRequirements struct
func GetResourceRequirements(i *operatorv1.InstallationSpec, name operatorv1.ComponentName) v1.ResourceRequirements {
	if i.ComponentResources != nil {
		for _, cr := range i.ComponentResources {
			if cr.ComponentName == name && cr.ResourceRequirements != nil {
				return *cr.ResourceRequirements
			}
		}
	}
	return v1.ResourceRequirements{}
}

func OperatorNamespace() string {
	v, ok := os.LookupEnv("OPERATOR_NAMESPACE")
	if ok {
		return v
	}
	return "tigera-operator"
}

func SecurityContext() *v1.SecurityContext {
	return &v1.SecurityContext{
		RunAsNonRoot:             types.BoolToPtr(true),
		AllowPrivilegeEscalation: types.BoolToPtr(false),
	}
}

// Creates the base pod security policy with the minimal required permissions to be overridden if necessary.
func BasePodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	falseBool := false
	ptrBoolFalse := &falseBool
	return &policyv1beta1.PodSecurityPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"seccomp.security.alpha.kubernetes.io/allowedProfileNames": "*",
			},
		},
		Spec: policyv1beta1.PodSecurityPolicySpec{
			Privileged:               false,
			AllowPrivilegeEscalation: ptrBoolFalse,
			RequiredDropCapabilities: []v1.Capability{
				v1.Capability("ALL"),
			},
			Volumes: []policyv1beta1.FSType{
				policyv1beta1.ConfigMap,
				policyv1beta1.EmptyDir,
				policyv1beta1.Projected,
				policyv1beta1.Secret,
				policyv1beta1.DownwardAPI,
				policyv1beta1.PersistentVolumeClaim,
			},
			HostNetwork: false,
			HostPorts: []policyv1beta1.HostPortRange{
				policyv1beta1.HostPortRange{
					Min: int32(0),
					Max: int32(65535),
				},
			},
			HostIPC: false,
			HostPID: false,
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
