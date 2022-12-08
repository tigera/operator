// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package egressgateway_test

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/egressgateway"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Egress Gateway rendering tests", func() {
	var installation *operatorv1.InstallationSpec
	var egw *operatorv1.EgressGateway
	var replicas int32 = 2
	var healthPort int32 = 8081
	logSeverity := "info"
	healthTimeoutDS := &metav1.Duration{30 * time.Second}
	interval := &metav1.Duration{20 * time.Second}
	timeout := &metav1.Duration{40 * time.Second}
	labels := map[string]string{"egress-code": "red"}

	topoConstraint := corev1.TopologySpreadConstraint{
		MaxSkew:           100,
		TopologyKey:       "topology.kubernetes.io/zone",
		WhenUnsatisfiable: "DoNotSchedule",
		LabelSelector:     &metav1.LabelSelector{MatchLabels: labels},
	}

	weightedPodAffinity := corev1.WeightedPodAffinityTerm{Weight: 100,
		PodAffinityTerm: corev1.PodAffinityTerm{LabelSelector: &metav1.LabelSelector{MatchLabels: labels},
			TopologyKey: "topology.kuberneted.io/zone"}}

	affinity := &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{weightedPodAffinity}}}

	BeforeEach(func() {
		// Initialize a default installation spec.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
		}
		egw = &operatorv1.EgressGateway{
			Spec: operatorv1.EgressGatewaySpec{
				Replicas:    &replicas,
				IPPools:     []string{"ippool-1", "ippool-2"},
				Labels:      labels,
				LogSeverity: &logSeverity,
				Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{
					Spec: &operatorv1.EgressGatewayDeploymentPodSpec{
						Affinity:     affinity,
						NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
						TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
							topoConstraint,
						},
					},
				},
				EgressGatewayFailureDetection: &operatorv1.EgressGatewayFailureDetection{
					HealthPort:             &healthPort,
					HealthTimeoutDataStore: healthTimeoutDS,
					ICMPProbes:             &operatorv1.ICMPProbes{IPs: []string{}, Timeout: timeout, Interval: interval},
					HTTPProbes:             &operatorv1.HTTPProbes{URLs: []string{}, Timeout: timeout, Interval: interval},
				},
			},
		}
		egw.Name = "egress-test"
		egw.Namespace = "test-ns"
	})

	It("should render EGW deployment", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "egress-test", ns: "test-ns", group: "apps", version: "v1", kind: "Deployment"},
		}

		component := egressgateway.EgressGateway(&egressgateway.Config{
			PullSecrets:       nil,
			Installation:      installation,
			OsType:            rmeta.OSTypeLinux,
			EgressGW:          egw,
			EgressGWVxlanVNI:  4097,
			EgressGWVxlanPort: 4790,
		})
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(1))
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
		dep := rtest.GetResource(resources, "egress-test", "test-ns", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(len(dep.Spec.Template.Spec.Containers)).To(Equal(1))
		Expect(len(dep.Spec.Template.Spec.InitContainers)).To(Equal(1))
		Expect(len(dep.Spec.Template.Spec.Volumes)).To(Equal(1))
		expectedVolume := corev1.Volume{
			Name: "policysync",
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver: "csi.tigera.io",
				},
			},
		}
		Expect(dep.Spec.Template.Spec.Volumes).To(ContainElement(expectedVolume))
		initContainer := dep.Spec.Template.Spec.InitContainers[0]
		egwContainer := dep.Spec.Template.Spec.Containers[0]
		expectedInitEnvVars := []corev1.EnvVar{
			{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
			{Name: "EGRESS_VXLAN_PORT", Value: "4790"},
		}
		for _, elem := range expectedInitEnvVars {
			Expect(initContainer.Env).To(ContainElement(elem))
		}
		expectedEnvVars := []corev1.EnvVar{
			{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
			{Name: "LOG_SEVERITY", Value: "info"},
			{Name: "HEALTH_TIMEOUT_DATASTORE", Value: "30s"},
			{Name: "ICMP_PROBE_INTERVAL", Value: "20s"},
			{Name: "ICMP_PROBE_TIMEOUT", Value: "40s"},
			{Name: "HTTP_PROBE_INTERVAL", Value: "20s"},
			{Name: "HTTP_PROBE_TIMEOUT", Value: "40s"},
			{Name: "HEALTH_PORT", Value: "8081"},
		}
		for _, elem := range expectedEnvVars {
			Expect(egwContainer.Env).To(ContainElement(elem))
		}
		ipPoolAnnotation := dep.Spec.Template.ObjectMeta.Annotations["cni.projectcalico.org/ipv4pools"]
		expectedIPPoolAnnotation := "[\"ippool-1\",\"ippool-2\"]"
		Expect(ipPoolAnnotation).To(Equal(expectedIPPoolAnnotation))

		Expect(dep.Spec.Template.ObjectMeta.Labels).To(Equal(labels))
		expectedPort := corev1.ContainerPort{
			ContainerPort: healthPort,
			Name:          "health",
			Protocol:      corev1.ProtocolTCP,
		}
		Expect(egwContainer.Ports).To(ContainElement(expectedPort))
		Expect(dep.Spec.Template.Spec.NodeSelector["kubernetes.io/os"]).To(Equal("linux"))
		expectedSecurityCtx := &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
		}
		Expect(egwContainer.SecurityContext).To(Equal(expectedSecurityCtx))
		initContainerPrivileges := true
		expectedInitSecurityCtx := &corev1.SecurityContext{Privileged: &initContainerPrivileges}
		Expect(initContainer.SecurityContext).To(Equal(expectedInitSecurityCtx))
		expectedRP := &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/readiness",
					Port: intstr.FromInt(int(healthPort)),
				},
			},
			InitialDelaySeconds: 3,
			TimeoutSeconds:      1,
			SuccessThreshold:    1,
			PeriodSeconds:       3,
		}
		Expect(egwContainer.ReadinessProbe).To(Equal(expectedRP))

		volumeMount := corev1.VolumeMount{Name: "policysync", MountPath: "/var/run"}
		Expect(egwContainer.VolumeMounts).To(ContainElement(volumeMount))

		Expect(dep.Spec.Template.Spec.TopologySpreadConstraints).To(ContainElement(topoConstraint))
		Expect(dep.Spec.Template.Spec.Affinity).To(Equal(affinity))
	})

	It("should have proper annotations and resources if aws is set", func() {
		recommendedQuantity := resource.NewQuantity(1, resource.DecimalSI)
		expectedResource := corev1.ResourceRequirements{
			Limits:   corev1.ResourceList{"projectcalico.org/aws-secondary-ipv4": *recommendedQuantity},
			Requests: corev1.ResourceList{"projectcalico.org/aws-secondary-ipv4": *recommendedQuantity},
		}

		nativeIP := operatorv1.NativeIPEnabled
		egw.Spec.AWS = &operatorv1.AwsEgressGateway{NativeIP: &nativeIP, ElasticIPs: []string{"1.2.3.4", "5.6.7.8"}}
		component := egressgateway.EgressGateway(&egressgateway.Config{
			PullSecrets:       nil,
			Installation:      installation,
			OsType:            rmeta.OSTypeLinux,
			EgressGW:          egw,
			EgressGWVxlanVNI:  4097,
			EgressGWVxlanPort: 4790,
		})
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(1))
		dep := rtest.GetResource(resources, "egress-test", "test-ns", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers[0].Resources).To(Equal(expectedResource))
		elasticIPAnnotation := dep.Spec.Template.ObjectMeta.Annotations["cni.projectcalico.org/awsElasticIPs"]
		Expect(elasticIPAnnotation).To(Equal("[\"1.2.3.4\",\"5.6.7.8\"]"))
	})
})
