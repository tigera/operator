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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
				TrustedCertBundle: certificatemanagement.CreateTrustedBundle(nil),
			},
			7, 0,
		),
		Entry("Should return objects to delete when variant is not Calico",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.TigeraSecureEnterprise,
				},
				TrustedCertBundle: certificatemanagement.CreateTrustedBundle(nil),
			},
			0, 7,
		),
	)

	DescribeTable("Whisker Deployment", func(cfg *whisker.Configuration, expected *appsv1.Deployment) {
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerName, whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(deployment).To(Equal(expected))
	},
		Entry("Should return objects to create when variant is Calico",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle: certificatemanagement.CreateTrustedBundle(nil),
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
										{Name: "GOLDMANE_HOST", Value: "localhost:7443"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts:    certificatemanagement.CreateTrustedBundle(nil).VolumeMounts(rmeta.OSTypeAny),
								},
								{
									Name:            whisker.GoldmaneContainerName,
									Image:           "",
									ImagePullPolicy: render.ImagePullPolicy(),
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "PORT", Value: "7443"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "tigera-ca-bundle",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-ca-bundle"},
										},
									},
								},
							},
						},
					},
				},
			},
		),

		Entry("Should configure guardian",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle: certificatemanagement.CreateTrustedBundle(nil),
				ManagementClusterConnection: &operatorv1.ManagementClusterConnection{
					Spec: operatorv1.ManagementClusterConnectionSpec{
						TLS: &operatorv1.ManagementClusterTLS{
							CA: operatorv1.CATypeTigera,
						},
					},
				},
				TunnelSecret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-tunnel-secret"}},
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
										{Name: "GOLDMANE_HOST", Value: "localhost:7443"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts:    certificatemanagement.CreateTrustedBundle(nil).VolumeMounts(rmeta.OSTypeAny),
								},
								{
									Name:            whisker.GoldmaneContainerName,
									Image:           "",
									ImagePullPolicy: render.ImagePullPolicy(),
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "PORT", Value: "7443"},
										{Name: "PUSH_URL", Value: "https://localhost:8080/api/v1/flows/bulk"},
										{Name: "CA_CERT_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
									},
									VolumeMounts:    []corev1.VolumeMount{{Name: "tigera-ca-bundle", ReadOnly: true, MountPath: "/etc/pki/tls/certs"}},
									SecurityContext: securitycontext.NewNonRootContext(),
								},
								{
									Name:            whisker.GuardianContainerName,
									Image:           "",
									ImagePullPolicy: render.ImagePullPolicy(),
									Env: []corev1.EnvVar{
										{Name: "GUARDIAN_PORT", Value: "9443"},
										{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
										{Name: "GUARDIAN_VOLTRON_URL"},
										{Name: "GUARDIAN_VOLTRON_CA_TYPE", Value: "Tigera"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts: []corev1.VolumeMount{
										{Name: "tigera-tunnel-secret-s", MountPath: "/certs"},
										{Name: "tigera-ca-bundle", ReadOnly: true, MountPath: "/etc/pki/tls/certs"},
									},
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "tigera-ca-bundle",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-ca-bundle"},
										},
									},
								},
								{
									Name:         "tigera-tunnel-secret-s",
									VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "tigera-tunnel-secret"}},
								},
							},
						},
					},
				},
			},
		),
	)
})
