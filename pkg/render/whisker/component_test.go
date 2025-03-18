// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package whisker_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/google/go-cmp/cmp"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var (
	defaultTLSKeyPair        = certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "key-pair"}}, nil, "")
	defaultTrustedCertBundle = certificatemanagement.CreateTrustedBundle(nil)
)

var _ = Describe("ComponentRendering", func() {
	DescribeTable("Creation and deletion counts", func(cfg *whisker.Configuration, creatObjs, delObjs int) {
		component := whisker.Whisker(cfg)
		objsToCreate, objsToDelete := component.Objects()
		Expect(objsToCreate).To(HaveLen(creatObjs))
		Expect(objsToDelete).To(HaveLen(delObjs))
	},
		Entry("Should return objects to create when variant is Calico",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle:     defaultTrustedCertBundle,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
			},
			4, 0,
		),
		Entry("Should return objects to delete when variant is not Calico",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.TigeraSecureEnterprise,
				},
				TrustedCertBundle:     defaultTrustedCertBundle,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
			},
			0, 4,
		),
	)

	DescribeTable("Whisker Deployment", func(cfg *whisker.Configuration, expected *appsv1.Deployment) {
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerName, whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(deployment).To(Equal(expected), cmp.Diff(deployment, expected))
	},
		Entry("Should return objects to create when variant is Calico",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle:     defaultTrustedCertBundle,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
			},
			&appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      whisker.WhiskerDeploymentName,
					Namespace: whisker.WhiskerNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.ToPtr(int32(1)),
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RecreateDeploymentStrategyType,
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Name: whisker.WhiskerDeploymentName,
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: whisker.WhiskerServiceAccountName,
							Tolerations:        append(rmeta.TolerateCriticalAddonsAndControlPlane, rmeta.TolerateGKEARM64NoSchedule),
							Containers: []corev1.Container{
								{
									Name:            whisker.WhiskerContainerName,
									Image:           "",
									ImagePullPolicy: render.ImagePullPolicy(),
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
								},
								{
									Name:            whisker.WhiskerBackendContainerName,
									Image:           "",
									ImagePullPolicy: render.ImagePullPolicy(),
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "PORT", Value: "3002"},
										{Name: "GOLDMANE_HOST", Value: "goldmane.calico-system.svc.cluster.local:7443"},
										{Name: "TLS_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "TLS_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts: append(
										defaultTrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux),
										defaultTLSKeyPair.VolumeMount(rmeta.OSTypeLinux)),
								},
							},
							Volumes: []corev1.Volume{
								defaultTrustedCertBundle.Volume(),
								defaultTLSKeyPair.Volume(),
							},
						},
					},
				},
			},
		),
	)
})

func GetOverriddenWhiskerDeployment(overrides *operatorv1.WhiskerDeployment) (*appsv1.Deployment, error) {
	component := whisker.Whisker(&whisker.Configuration{
		Installation: &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderGKE,
			Variant:            operatorv1.Calico,
		},
		TrustedCertBundle:     defaultTrustedCertBundle,
		WhiskerBackendKeyPair: defaultTLSKeyPair,
		Whisker: &operatorv1.Whisker{
			Spec: operatorv1.WhiskerSpec{
				WhiskerDeployment: overrides,
			},
		},
	})

	objsToCreate, _ := component.Objects()
	return rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerName, whisker.WhiskerNamespace)
}
