// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package applicationlayer_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// fakeCertPair is a minimal stub that satisfies certificatemanagement.KeyPairInterface
// for unit tests that only need the render functions to produce objects without real TLS
// material.
type fakeCertPair struct{}

var _ certificatemanagement.KeyPairInterface = (*fakeCertPair)(nil)

func (f *fakeCertPair) UseCertificateManagement() bool { return false }
func (f *fakeCertPair) BYO() bool                      { return true }
func (f *fakeCertPair) InitContainer(_ string, _ *corev1.SecurityContext) corev1.Container {
	return corev1.Container{}
}
func (f *fakeCertPair) VolumeMount(_ rmeta.OSType) corev1.VolumeMount {
	return corev1.VolumeMount{Name: "tls-certs", MountPath: "/tls"}
}
func (f *fakeCertPair) VolumeMountKeyFilePath() string         { return "/tls/tls.key" }
func (f *fakeCertPair) VolumeMountCertificateFilePath() string { return "/tls/tls.crt" }
func (f *fakeCertPair) Volume() corev1.Volume {
	return corev1.Volume{
		Name: "tls-certs",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{SecretName: "fake-tls"},
		},
	}
}
func (f *fakeCertPair) Secret(_ string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "fake-tls"}}
}
func (f *fakeCertPair) HashAnnotationKey() string   { return "hash.operator.tigera.io/fake-tls" }
func (f *fakeCertPair) HashAnnotationValue() string { return "fake-hash" }
func (f *fakeCertPair) Warnings() string            { return "" }
func (f *fakeCertPair) GetCertificatePEM() []byte   { return []byte("fake-ca") }
func (f *fakeCertPair) GetIssuer() certificatemanagement.CertificateInterface {
	return nil
}
func (f *fakeCertPair) GetName() string      { return "fake-tls" }
func (f *fakeCertPair) GetNamespace() string { return "calico-system" }

var minimalInstallation = operatorv1.InstallationSpec{
	KubernetesProvider: operatorv1.ProviderNone,
}

func TestWAFAdmissionWebhookComponents_HasExpectedKinds(t *testing.T) {
	objs := applicationlayer.WAFAdmissionWebhookComponents(&minimalInstallation, "tigera/waf-admission-controller:v0.1.0", &fakeCertPair{})
	got := map[string]int{}
	for _, o := range objs {
		got[o.GetObjectKind().GroupVersionKind().Kind]++
	}
	require.Equal(t, 1, got["Deployment"], "expected 1 Deployment")
	require.Equal(t, 1, got["Service"], "expected 1 Service")
	require.Equal(t, 1, got["ServiceAccount"], "expected 1 ServiceAccount")
	require.Equal(t, 1, got["ClusterRole"], "expected 1 ClusterRole")
	require.Equal(t, 1, got["ClusterRoleBinding"], "expected 1 ClusterRoleBinding")
	require.Equal(t, 1, got["ValidatingWebhookConfiguration"], "expected 1 ValidatingWebhookConfiguration")
	require.Len(t, objs, 6, "expected exactly 6 objects")
}

