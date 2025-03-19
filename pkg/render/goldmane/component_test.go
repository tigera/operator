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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/goldmane"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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
				Goldmane:              &operatorv1.Goldmane{},
			},
			7, 0,
		),
		Entry("Should return objects to delete when variant is not Calico",
			&goldmane.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.TigeraSecureEnterprise,
				},
				TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(nil),
				GoldmaneServerKeyPair: defaultTLSKeyPair,
				Goldmane:              &operatorv1.Goldmane{},
			},
			0, 7,
		),
	)

	DescribeTable("Goldmane Deployment", func(cfg *goldmane.Configuration, expected *appsv1.Deployment) {
		component := goldmane.Goldmane(cfg)
		objsToCreate, _ := component.Objects()

		deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, goldmane.GoldmaneName, goldmane.GoldmaneNamespace)
		Expect(err).ShouldNot(HaveOccurred())

		// Check commonly changed fields explicitly for ease of diagnosis.
		Expect(deployment.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expected.Spec.Template.Spec.Containers[0].Env))
		Expect(deployment.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expected.Spec.Template.Spec.Containers[0].VolumeMounts))
		Expect(deployment.Spec.Template.Spec.Volumes).To(ConsistOf(expected.Spec.Template.Spec.Volumes))

		// Catch-all for the rest of the fields.
		Expect(deployment).To(Equal(expected), cmp.Diff(deployment, expected))
	},
		Entry("Should return objects to create when variant is Calico",
			&goldmane.Configuration{
				ClusterDomain: "cluster.local",
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(nil),
				GoldmaneServerKeyPair: defaultTLSKeyPair,
				Goldmane:              &operatorv1.Goldmane{},
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
										{Name: "PUSH_URL", Value: "https://tigera-guardian.calico-system.svc.cluster.local:443/api/v1/flows/bulk"},
										{Name: "FILE_CONFIG_PATH", Value: "/config/config.json"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts: append(
										[]corev1.VolumeMount{defaultTLSKeyPair.VolumeMount(rmeta.OSTypeLinux)},
										defaultTrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux)[0],
										corev1.VolumeMount{
											Name:      "config",
											ReadOnly:  true,
											MountPath: "/config",
										},
									),
								},
							},
							Volumes: []corev1.Volume{
								defaultTLSKeyPair.Volume(),
								defaultTrustedCertBundle.Volume(),
								{
									Name: "config",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: "goldmane"},
										},
									},
								},
							},
						},
					},
				},
			},
		),
	)

	It("Should apply overrides", func() {
		affinity := &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "custom-affinity-key",
									Operator: corev1.NodeSelectorOpExists,
								},
							},
						},
					},
				},
			},
		}
		goldmaneResources := &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
		}
		nodeSelector := map[string]string{
			"some-selector": "an override of a default nodeSelector key",
		}
		podLabels := map[string]string{
			"extra-label": "extra",
		}
		podAnnotations := map[string]string{
			"extra-annotation": "extra",
		}
		tolerations := []corev1.Toleration{
			{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			},
		}
		topologyConstraints := []corev1.TopologySpreadConstraint{
			{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
				},
			},
		}

		priorityClassName := "priority-class"

		overrides := &operatorv1.GoldmaneDeployment{
			Spec: &operatorv1.GoldmaneDeploymentSpec{
				Template: &operatorv1.GoldmaneDeploymentPodTemplateSpec{
					Metadata: &operatorv1.Metadata{
						Labels:      podLabels,
						Annotations: podAnnotations,
					},
					Spec: &operatorv1.GoldmaneDeploymentPodSpec{
						Affinity: affinity,
						Containers: []operatorv1.GoldmaneDeploymentContainer{
							{
								Name:      "goldmane",
								Resources: goldmaneResources,
							},
						},
						NodeSelector:              nodeSelector,
						TopologySpreadConstraints: topologyConstraints,
						Tolerations:               tolerations,
						PriorityClassName:         priorityClassName,
					},
				},
			},
		}

		deployment, err := GetOverriddenGoldmaneDeployment(overrides)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(deployment.Spec.Template.ObjectMeta.Labels).To(Equal(podLabels))
		Expect(deployment.Spec.Template.ObjectMeta.Annotations).To(Equal(podAnnotations))
		Expect(deployment.Spec.Template.Spec.Affinity).To(Equal(affinity))
		Expect(deployment.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologyConstraints))
		Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
		Expect(deployment.Spec.Template.Spec.Tolerations).To(Equal(tolerations))
		Expect(deployment.Spec.Template.Spec.PriorityClassName).To(Equal(priorityClassName))
		Expect(deployment.Spec.Template.Spec.Containers[0].Resources).To(Equal(*goldmaneResources))
	})
})

func GetOverriddenGoldmaneDeployment(overrides *operatorv1.GoldmaneDeployment) (*appsv1.Deployment, error) {
	component := goldmane.Goldmane(&goldmane.Configuration{
		Installation: &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderGKE,
			Variant:            operatorv1.Calico,
		},
		TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(nil),
		GoldmaneServerKeyPair: defaultTLSKeyPair,
		Goldmane: &operatorv1.Goldmane{
			Spec: operatorv1.GoldmaneSpec{
				GoldmaneDeployment: overrides,
			},
		},
	})
	objsToCreate, _ := component.Objects()
	return rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, goldmane.GoldmaneName, whisker.GoldmaneNamespace)
}
