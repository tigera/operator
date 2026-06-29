// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package otelcollector_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/go-cmp/cmp"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/otelcollector"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("OTelCollector rendering", func() {
	var defaultInstallation *operatorv1.InstallationSpec

	BeforeEach(func() {
		defaultInstallation = &operatorv1.InstallationSpec{
			KubernetesProvider:   operatorv1.ProviderGKE,
			ControlPlaneReplicas: ptr.To(int32(2)),
		}
	})

	DescribeTable("Object counts",
		func(cfg *otelcollector.Configuration, createCount, deleteCount int) {
			component := otelcollector.OTelCollector(cfg)
			toCreate, toDelete := component.Objects()
			Expect(toCreate).To(HaveLen(createCount))
			Expect(toDelete).To(HaveLen(deleteCount))
		},
		Entry("logs and metrics enabled",
			&otelcollector.Configuration{
				Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderGKE},
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs:      &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
					Metrics:   &operatorv1.OTelMetrics{Enabled: ptr.To(operatorv1.OTelMetricsEnable)},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			},
			7, 0,
		),
		Entry("logs only",
			&otelcollector.Configuration{
				Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderGKE},
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs:      &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelAuditLog}},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			},
			7, 0,
		),
		Entry("metrics only",
			&otelcollector.Configuration{
				Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderGKE},
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Metrics:   &operatorv1.OTelMetrics{Enabled: ptr.To(operatorv1.OTelMetricsEnable)},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			},
			7, 0,
		),
		Entry("no logs, no metrics",
			&otelcollector.Configuration{
				Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderGKE},
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			},
			7, 0,
		),
	)

	Context("StatefulSet rendering", func() {
		It("should render the expected statefulset", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs:      &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			component := otelcollector.OTelCollector(cfg)
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := component.Objects()

			expected := &appsv1.StatefulSet{
				TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      otelcollector.OTelCollectorStatefulSetName,
					Namespace: otelcollector.OTelCollectorNamespace,
				},
				Spec: appsv1.StatefulSetSpec{
					Replicas:    ptr.To(int32(2)),
					ServiceName: otelcollector.OTelCollectorServiceName,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"k8s-app": otelcollector.OTelCollectorStatefulSetName},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Name:   otelcollector.OTelCollectorStatefulSetName,
							Labels: map[string]string{"k8s-app": otelcollector.OTelCollectorStatefulSetName},
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: otelcollector.OTelCollectorServiceAccountName,
							Tolerations:        append(rmeta.TolerateCriticalAddonsAndControlPlane, rmeta.TolerateGKEARM64NoSchedule),
							Containers: []corev1.Container{
								{
									Name:    otelcollector.OTelCollectorContainerName,
									Image:   "gcr.io/unique-caldron-775/cnx/tigera/calico:master",
									Command: []string{"/usr/bin/otelcol", "--config=/etc/otel/config.yaml"},
									Ports: []corev1.ContainerPort{
										{Name: "otlp-grpc", ContainerPort: otelcollector.OTLPGRPCPort, Protocol: corev1.ProtocolTCP},
										{Name: "otlp-http", ContainerPort: otelcollector.OTLPHTTPPort, Protocol: corev1.ProtocolTCP},
										{Name: "health", ContainerPort: otelcollector.HealthCheckPort, Protocol: corev1.ProtocolTCP},
									},
									Resources: corev1.ResourceRequirements{
										Limits: corev1.ResourceList{
											corev1.ResourceMemory: resource.MustParse(otelcollector.DefaultMemoryLimit),
										},
										Requests: corev1.ResourceList{
											corev1.ResourceMemory: resource.MustParse(otelcollector.DefaultMemoryRequest),
										},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									ReadinessProbe: &corev1.Probe{
										ProbeHandler: corev1.ProbeHandler{
											HTTPGet: &corev1.HTTPGetAction{
												Path: "/",
												Port: intstr.FromInt32(otelcollector.HealthCheckPort),
											},
										},
										PeriodSeconds: 10,
									},
									LivenessProbe: &corev1.Probe{
										ProbeHandler: corev1.ProbeHandler{
											HTTPGet: &corev1.HTTPGetAction{
												Path: "/",
												Port: intstr.FromInt32(otelcollector.HealthCheckPort),
											},
										},
										PeriodSeconds: 10,
									},
									VolumeMounts: []corev1.VolumeMount{
										{Name: "config", MountPath: "/etc/otel", ReadOnly: true},
									},
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "config",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: otelcollector.OTelCollectorConfigMapName},
										},
									},
								},
							},
						},
					},
				},
			}

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OTelCollectorStatefulSetName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(statefulSet.Spec.Template.Spec.Containers[0].Ports).To(ConsistOf(expected.Spec.Template.Spec.Containers[0].Ports))
			Expect(statefulSet.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expected.Spec.Template.Spec.Containers[0].VolumeMounts))
			Expect(statefulSet.Spec.Template.Spec.Volumes).To(ConsistOf(expected.Spec.Template.Spec.Volumes))
			Expect(statefulSet).To(Equal(expected), cmp.Diff(statefulSet, expected))
		})

		It("should include TLS volumes and mounts when metrics with certs are enabled", func() {
			tlsKeyPair := certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "client-tls"}}, nil, "")
			trustedBundle := certificatemanagement.CreateTrustedBundle(nil)

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Metrics:   &operatorv1.OTelMetrics{Enabled: ptr.To(operatorv1.OTelMetricsEnable)},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
				ClientTLSSecret:   tlsKeyPair,
				TrustedCertBundle: trustedBundle,
			}
			component := otelcollector.OTelCollector(cfg)
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := component.Objects()

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OTelCollectorStatefulSetName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(len(statefulSet.Spec.Template.Spec.Volumes)).To(BeNumerically(">", 1))
			Expect(len(statefulSet.Spec.Template.Spec.Containers[0].VolumeMounts)).To(BeNumerically(">", 1))
		})

		It("should include receiver TLS volumes and mounts when logs with certs are enabled", func() {
			receiverKeyPair := certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector-tls"}}, nil, "")
			trustedBundle := certificatemanagement.CreateTrustedBundle(nil)

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs:      &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
				ReceiverTLSSecret: receiverKeyPair,
				TrustedCertBundle: trustedBundle,
			}
			component := otelcollector.OTelCollector(cfg)
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := component.Objects()

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OTelCollectorStatefulSetName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(len(statefulSet.Spec.Template.Spec.Volumes)).To(BeNumerically(">", 1))
			Expect(len(statefulSet.Spec.Template.Spec.Containers[0].VolumeMounts)).To(BeNumerically(">", 1))
		})
	})

	Context("ConfigMap content", func() {
		It("should include otlp receiver when logs are enabled", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs:      &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("otlp:"))
			Expect(config).To(ContainSubstring("0.0.0.0:4318"))
			Expect(config).To(ContainSubstring("logs:"))
			Expect(config).To(ContainSubstring("receivers: [otlp]"))
		})

		It("should include receiver TLS config when logs with certs are enabled", func() {
			receiverKeyPair := certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector-tls"}}, nil, "")
			trustedBundle := certificatemanagement.CreateTrustedBundle(nil)

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs:      &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
				ReceiverTLSSecret: receiverKeyPair,
				TrustedCertBundle: trustedBundle,
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("otlp:"))
			Expect(config).To(ContainSubstring("cert_file:"))
			Expect(config).To(ContainSubstring("key_file:"))
			Expect(config).To(ContainSubstring("client_ca_file:"))
		})

		It("should include prometheus receiver when metrics are enabled", func() {
			tlsKeyPair := certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "client-tls"}}, nil, "")
			trustedBundle := certificatemanagement.CreateTrustedBundle(nil)

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Metrics:   &operatorv1.OTelMetrics{Enabled: ptr.To(operatorv1.OTelMetricsEnable)},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
				ClientTLSSecret:   tlsKeyPair,
				TrustedCertBundle: trustedBundle,
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("prometheus:"))
			Expect(config).To(ContainSubstring("kubernetes_sd_configs"))
			Expect(config).To(ContainSubstring("tls_config:"))
			Expect(config).To(ContainSubstring("server_name: calico-node-metrics"))
			Expect(config).To(ContainSubstring("calico-metrics-port|calico-bgp-metrics-port"))
			Expect(config).To(ContainSubstring("metrics:"))
			Expect(config).To(ContainSubstring("receivers: [prometheus]"))
			Expect(config).To(ContainSubstring("exporters: [otlp/backend]"))
		})

		It("should not include receivers or pipelines when logs and metrics are disabled", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).NotTo(ContainSubstring("otlp:"))
			Expect(config).NotTo(ContainSubstring("prometheus:"))
			Expect(config).NotTo(ContainSubstring("logs:"))
			Expect(config).NotTo(ContainSubstring("metrics:"))
		})

		It("should use otlphttp prefix for HTTP exporters", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs: &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
					Exporters: []operatorv1.OTelExporter{
						{Name: "httpbackend", Endpoint: "https://otlp.example.com:443", Protocol: operatorv1.OTelProtocolHTTP},
					},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("otlphttp/httpbackend:"))
			Expect(config).To(ContainSubstring("exporters: [otlphttp/httpbackend]"))
		})

		It("should use otlp prefix for gRPC exporters", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs: &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
					Exporters: []operatorv1.OTelExporter{
						{Name: "grpcbackend", Endpoint: "otlp.example.com:4317", Protocol: operatorv1.OTelProtocolGRPC},
					},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("otlp/grpcbackend:"))
			Expect(config).To(ContainSubstring("exporters: [otlp/grpcbackend]"))
		})

		It("should list multiple exporters in pipelines", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Logs: &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
					Exporters: []operatorv1.OTelExporter{
						{Name: "first", Endpoint: "first.example.com:4317"},
						{Name: "second", Endpoint: "https://second.example.com", Protocol: operatorv1.OTelProtocolHTTP},
					},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("exporters: [otlp/first, otlphttp/second]"))
		})

		It("should always include the health_check extension", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			cm, err := rtest.GetResourceOfType[*corev1.ConfigMap](objs, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			config := cm.Data["config.yaml"]
			Expect(config).To(ContainSubstring("extensions:"))
			Expect(config).To(ContainSubstring("health_check:"))
			Expect(config).To(ContainSubstring("0.0.0.0:13133"))
			Expect(config).To(ContainSubstring("extensions: [health_check]"))
		})
	})

	Context("Service", func() {
		It("should expose the OTLP HTTP port", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			svc, err := rtest.GetResourceOfType[*corev1.Service](objs, otelcollector.OTelCollectorServiceName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(svc.Spec.Ports).To(HaveLen(1))
			Expect(svc.Spec.Ports[0].Port).To(Equal(int32(otelcollector.OTLPHTTPPort)))
			Expect(svc.Spec.Ports[0].Name).To(Equal("otlp-http"))
			Expect(svc.Spec.Selector).To(Equal(map[string]string{"k8s-app": otelcollector.OTelCollectorStatefulSetName}))
		})
	})

	Context("RBAC", func() {
		It("should render the expected service account, cluster role, and cluster role binding", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()

			sa, err := rtest.GetResourceOfType[*corev1.ServiceAccount](objs, otelcollector.OTelCollectorServiceAccountName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(sa).NotTo(BeNil())

			cr, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objs, otelcollector.OTelCollectorClusterRoleName, "")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Rules).To(HaveLen(1))
			Expect(cr.Rules[0].Resources).To(ConsistOf("nodes", "pods", "services", "endpoints"))

			crb, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objs, otelcollector.OTelCollectorClusterRoleName, "")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(crb.RoleRef.Name).To(Equal(otelcollector.OTelCollectorClusterRoleName))
			Expect(crb.Subjects).To(HaveLen(1))
			Expect(crb.Subjects[0].Name).To(Equal(otelcollector.OTelCollectorServiceAccountName))
		})
	})

	Context("NetworkPolicy", func() {
		It("should allow ingress on the OTLP HTTP port", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OTelCollectorPolicyName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(np.Spec.Ingress).To(HaveLen(1))
			Expect(np.Spec.Ingress[0].Action).To(Equal(v3.Allow))
			Expect(np.Spec.Types).To(ConsistOf(v3.PolicyTypeIngress, v3.PolicyTypeEgress))
		})

		It("should add kube API server and prometheus egress rules when metrics are enabled", func() {
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Metrics:   &operatorv1.OTelMetrics{Enabled: ptr.To(operatorv1.OTelMetricsEnable)},
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()

			np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objs, otelcollector.OTelCollectorPolicyName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(len(np.Spec.Egress)).To(BeNumerically(">=", 4))
		})
	})

	Context("StatefulSet overrides", func() {
		It("should apply overrides from the CR", func() {
			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			containerResources := &corev1.ResourceRequirements{
				Limits:   corev1.ResourceList{"cpu": resource.MustParse("500m")},
				Requests: corev1.ResourceList{"cpu": resource.MustParse("100m")},
			}
			nodeSelector := map[string]string{"zone": "us-west-2a"}
			tolerations := []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "otel"}}
			topologyConstraints := []corev1.TopologySpreadConstraint{{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "otel-collector"}},
			}}
			podLabels := map[string]string{"extra-label": "value"}
			podAnnotations := map[string]string{"extra-annotation": "value"}
			priorityClassName := "system-cluster-critical"

			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
					OTelCollectorStatefulSet: &operatorv1.OTelCollectorStatefulSet{
						Spec: &operatorv1.OTelCollectorStatefulSetSpec{
							Template: &operatorv1.OTelCollectorStatefulSetPodTemplateSpec{
								Metadata: &operatorv1.Metadata{
									Labels:      podLabels,
									Annotations: podAnnotations,
								},
								Spec: &operatorv1.OTelCollectorStatefulSetPodSpec{
									Affinity: affinity,
									Containers: []operatorv1.OTelCollectorStatefulSetContainer{{
										Name:      "otel-collector",
										Resources: containerResources,
									}},
									NodeSelector:              nodeSelector,
									Tolerations:               tolerations,
									TopologySpreadConstraints: topologyConstraints,
									PriorityClassName:         priorityClassName,
								},
							},
						},
					},
				},
			}

			component := otelcollector.OTelCollector(cfg)
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			objs, _ := component.Objects()

			statefulSet, err := rtest.GetResourceOfType[*appsv1.StatefulSet](objs, otelcollector.OTelCollectorStatefulSetName, otelcollector.OTelCollectorNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(statefulSet.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue("extra-label", "value"))
			Expect(statefulSet.Spec.Template.ObjectMeta.Labels).To(HaveKeyWithValue("k8s-app", otelcollector.OTelCollectorStatefulSetName))
			Expect(statefulSet.Spec.Template.ObjectMeta.Annotations).To(Equal(podAnnotations))
			Expect(statefulSet.Spec.Template.Spec.Affinity).To(Equal(affinity))
			Expect(statefulSet.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
			Expect(statefulSet.Spec.Template.Spec.Tolerations).To(Equal(tolerations))
			Expect(statefulSet.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologyConstraints))
			Expect(statefulSet.Spec.Template.Spec.PriorityClassName).To(Equal(priorityClassName))
			Expect(statefulSet.Spec.Template.Spec.Containers[0].Resources).To(Equal(*containerResources))
		})
	})

	Context("Pull secrets", func() {
		It("should include pull secrets when configured", func() {
			pullSecrets := []*corev1.Secret{
				{ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: "tigera-operator"}},
			}
			cfg := &otelcollector.Configuration{
				Installation: defaultInstallation,
				PullSecrets:  pullSecrets,
				OTelCollector: &operatorv1.OTelCollectorSpec{
					Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
				},
			}
			objs, _ := otelcollector.OTelCollector(cfg).Objects()
			// 7 base objects + 1 copied pull secret
			Expect(objs).To(HaveLen(8))
		})
	})

	It("should support Linux OS type", func() {
		component := otelcollector.OTelCollector(&otelcollector.Configuration{
			Installation: defaultInstallation,
			OTelCollector: &operatorv1.OTelCollectorSpec{
				Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
			},
		})
		Expect(component.SupportedOSType()).To(Equal(rmeta.OSTypeLinux))
	})

})
