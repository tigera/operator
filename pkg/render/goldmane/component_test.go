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

package goldmane_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/google/go-cmp/cmp"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/goldmane"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	defaultTLSKeyPair        = certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "key-pair"}}, nil, "")
	defaultTrustedCertBundle = certificatemanagement.CreateTrustedBundle(nil)
)

var _ = Describe("ComponentRendering", func() {
	DescribeTable("Creation and deletion counts", func(cfg *goldmane.Configuration, creatObjs, delObjs int) {
		component := goldmane.Goldmane(cfg)
		objsToCreate, objsToDelete := component.Objects()
		Expect(objsToCreate).To(HaveLen(creatObjs))
		Expect(objsToDelete).To(HaveLen(delObjs))
	},
		Entry("Should return objects to create when variant is Calico",
			&goldmane.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(nil),
				GoldmaneServerKeyPair: defaultTLSKeyPair,
			},
			6, 0,
		),
		Entry("Should return objects to delete when variant is not Calico",
			&goldmane.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.TigeraSecureEnterprise,
				},
				TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(nil),
				GoldmaneServerKeyPair: defaultTLSKeyPair,
			},
			0, 6,
		),
	)

	DescribeTable("Goldmane Deployment", func(cfg *goldmane.Configuration, expected *appsv1.Deployment) {
		component := goldmane.Goldmane(cfg)
		objsToCreate, _ := component.Objects()

		deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, goldmane.GoldmaneName, goldmane.GoldmaneNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(deployment).To(Equal(expected), cmp.Diff(deployment, expected))
	},
		Entry("Should return objects to create when variant is Calico",
			&goldmane.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(nil),
				GoldmaneServerKeyPair: defaultTLSKeyPair,
			},
			&appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:        goldmane.GoldmaneDeploymentName,
					Namespace:   goldmane.GoldmaneNamespace,
					Annotations: map[string]string{"hash.operator.tigera.io/key-pair": "e9e6e60e8b6007cbf14a325c3fa1f1692412315a"},
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.ToPtr(int32(1)),
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RecreateDeploymentStrategyType,
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Name: goldmane.GoldmaneDeploymentName,
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: goldmane.GoldmaneServiceAccountName,
							Tolerations:        append(rmeta.TolerateCriticalAddonsAndControlPlane, rmeta.TolerateGKEARM64NoSchedule),
							Containers: []corev1.Container{
								{
									Name:            goldmane.GoldmaneContainerName,
									Image:           "",
									ImagePullPolicy: render.ImagePullPolicy(),
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "PORT", Value: "7443"},
										{Name: "SERVER_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "SERVER_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
										{Name: "CA_CERT_PATH", Value: defaultTrustedCertBundle.MountPath()},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts: append(
										[]corev1.VolumeMount{defaultTLSKeyPair.VolumeMount(rmeta.OSTypeLinux)},
										defaultTrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux)...),
								},
							},
							Volumes: []corev1.Volume{
								defaultTLSKeyPair.Volume(),
								defaultTrustedCertBundle.Volume(),
							},
						},
					},
				},
			},
		),
	)
})
