// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/go-cmp/cmp"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var (
	defaultWhiskerKeyPair        = certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: whisker.WhiskerKeyPairSecret}}, nil, "")
	defaultTLSKeyPair            = certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "key-pair"}}, nil, "")
	defaultTrustedCertBundle     = certificatemanagement.CreateTrustedBundle(nil)
	numExpectedObjects           = 5
	numEnterpriseExpectedObjects = 6 // ServiceAccount + Deployment + NetworkPolicy + ClusterRole + ClusterRoleBinding + backend Service (no nginx ConfigMap or UI Service)

	// The deprecated k8s NetworkPolicy plus the other variant's objects.
	numCalicoDeletedObjects     = 4 // + backend ClusterRole, ClusterRoleBinding, and Service
	numEnterpriseDeletedObjects = 3 // + nginx ConfigMap and UI Service

	// calicoImageRef resolves the combined calico/calico image exactly as the
	// renderer does, so the expected image tracks the pinned ComponentCalico
	// version on any branch (:master on master, :v3.32.x on release-v1.43)
	// rather than a hardcoded tag.
	calicoImageRef, _           = components.GetReference(components.CombinedCalicoImage(&operatorv1.InstallationSpec{Variant: operatorv1.Calico}), "", "", "", nil)
	enterpriseCalicoImageRef, _ = components.GetReference(components.CombinedCalicoImage(&operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}), "", "", "", nil)
	// whiskerImageRef resolves the whisker image the same way the renderer does.
	whiskerImageRef, _ = components.GetReference(components.ComponentCalicoWhisker, "", "", "", nil)
)

var _ = Describe("ComponentRendering", func() {
	DescribeTable("Creation and deletion counts", func(cfg *whisker.Configuration, createObjs, delObjs int) {
		component := whisker.Whisker(cfg)
		objsToCreate, objsToDelete := component.Objects()
		Expect(objsToCreate).To(HaveLen(createObjs))
		Expect(objsToDelete).To(HaveLen(delObjs))
	},
		Entry("Should return the whisker objects to create",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.Calico,
				},
				TrustedCertBundle:     defaultTrustedCertBundle,
				WhiskerKeyPair:        defaultWhiskerKeyPair,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
				Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			},
			numExpectedObjects, numCalicoDeletedObjects,
		),
		Entry("Should return objects to create when variant is CalicoEnterprise",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.CalicoEnterprise,
				},
				TrustedCertBundle: defaultTrustedCertBundle,
				// No WhiskerKeyPair: the controller creates it only for OSS.
				WhiskerBackendKeyPair: defaultTLSKeyPair,
				Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			},
			numEnterpriseExpectedObjects, numEnterpriseDeletedObjects,
		),
	)

	DescribeTable("Whisker Deployment", func(cfg *whisker.Configuration, expected *appsv1.Deployment) {
		if cfg.Installation.Variant.IsEnterprise() {
			DeferCleanup(components.UseImages(components.EnterpriseImages))
		}
		component := whisker.Whisker(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
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
				WhiskerKeyPair:        defaultWhiskerKeyPair,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
				Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
				ClusterID:             "test-cluster-id",
				CalicoVersion:         "test-calico-version",
				ClusterType:           "test-cluster-type",
				ClusterDomain:         "cluster.domain",
			},
			&appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      whisker.WhiskerDeploymentName,
					Namespace: whisker.WhiskerNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To(int32(1)),
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RecreateDeploymentStrategyType,
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Name: whisker.WhiskerDeploymentName,
							Annotations: map[string]string{
								defaultWhiskerKeyPair.HashAnnotationKey(): defaultWhiskerKeyPair.HashAnnotationValue(),
								defaultTLSKeyPair.HashAnnotationKey():     defaultTLSKeyPair.HashAnnotationValue(),
							},
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: whisker.WhiskerServiceAccountName,
							Tolerations:        append(rmeta.TolerateCriticalAddonsAndControlPlane, rmeta.TolerateGKEARM64NoSchedule),
							Containers: []corev1.Container{
								{
									Name:  whisker.WhiskerContainerName,
									Image: whiskerImageRef,
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "CALICO_VERSION", Value: "test-calico-version"},
										{Name: "CLUSTER_ID", Value: "test-cluster-id"},
										{Name: "CLUSTER_TYPE", Value: "test-cluster-type"},
										{Name: "NOTIFICATIONS", Value: "Enabled"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "nginx-config",
											MountPath: "/etc/nginx/conf.d",
											ReadOnly:  true,
										},
										defaultWhiskerKeyPair.VolumeMount(rmeta.OSTypeLinux),
									},
								},
								{
									Name:    whisker.WhiskerBackendContainerName,
									Image:   calicoImageRef,
									Command: []string{"/usr/bin/calico", "component", "whisker-backend"},
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "PORT", Value: "3002"},
										{Name: "TLS_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "TLS_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
										{Name: "SERVER_TLS_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "SERVER_TLS_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
										{Name: "GOLDMANE_HOST", Value: "goldmane.calico-system.svc.cluster.domain:7443"},
									},
									SecurityContext: securitycontext.NewNonRootContext(),
									VolumeMounts: append(
										defaultTrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux),
										defaultTLSKeyPair.VolumeMount(rmeta.OSTypeLinux)),
								},
							},
							Volumes: []corev1.Volume{
								defaultTrustedCertBundle.Volume(),
								defaultWhiskerKeyPair.Volume(),
								defaultTLSKeyPair.Volume(),
								{
									Name: "nginx-config",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: "whisker-nginx-config"},
										},
									},
								},
							},
						},
					},
				},
			},
		),
		Entry("Should return enterprise deployment with Linseed env vars when variant is CalicoEnterprise",
			&whisker.Configuration{
				Installation: &operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderGKE,
					Variant:            operatorv1.CalicoEnterprise,
				},
				TrustedCertBundle:     defaultTrustedCertBundle,
				WhiskerBackendKeyPair: defaultTLSKeyPair,
				Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
				ClusterID:             "test-cluster-id",
				CalicoVersion:         "test-calico-version",
				ClusterType:           "test-cluster-type",
				ClusterDomain:         "cluster.domain",
			},
			&appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      whisker.WhiskerDeploymentName,
					Namespace: whisker.WhiskerNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To(int32(1)),
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RecreateDeploymentStrategyType,
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Name: whisker.WhiskerDeploymentName,
							Annotations: map[string]string{
								defaultTLSKeyPair.HashAnnotationKey(): defaultTLSKeyPair.HashAnnotationValue(),
							},
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: whisker.WhiskerServiceAccountName,
							Tolerations:        append(rmeta.TolerateCriticalAddonsAndControlPlane, rmeta.TolerateGKEARM64NoSchedule),
							Containers: []corev1.Container{
								{
									Name:    whisker.WhiskerBackendContainerName,
									Image:   enterpriseCalicoImageRef,
									Command: []string{"/usr/bin/calico", "component", "whisker-backend"},
									Env: []corev1.EnvVar{
										{Name: "LOG_LEVEL", Value: "INFO"},
										{Name: "PORT", Value: "3002"},
										{Name: "TLS_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "TLS_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
										{Name: "SERVER_TLS_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "SERVER_TLS_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
										{Name: "WHISKER_BACKEND_UPSTREAM", Value: "linseed"},
										{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
										{Name: "LINSEED_CA_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
										{Name: "LINSEED_TOKEN_PATH", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
										{Name: "LINSEED_CLUSTER_ID", Value: render.DefaultElasticsearchClusterName},
										{Name: "LINSEED_CLIENT_CERT_PATH", Value: defaultTLSKeyPair.VolumeMountCertificateFilePath()},
										{Name: "LINSEED_CLIENT_KEY_PATH", Value: defaultTLSKeyPair.VolumeMountKeyFilePath()},
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

	It("should render network policy with Goldmane egress for Calico variant", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerKeyPair:        defaultWhiskerKeyPair,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, whisker.WhiskerPolicyName, whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(np.Spec.Egress).To(HaveLen(2))
		Expect(np.Spec.Egress[0].Destination.Selector).To(Equal(networkpolicy.KubernetesAppSelector(whisker.GoldmaneDeploymentName)))
		Expect(np.Spec.Egress[0].Destination.Ports).To(Equal(networkpolicy.Ports(whisker.GoldmaneServicePort)))
	})

	It("should render Linseed RBAC for enterprise variant", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.CalicoEnterprise,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		cr, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, whisker.WhiskerBackendClusterRoleName, "")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cr.Rules).To(HaveLen(6))
		Expect(cr.Rules[0].APIGroups).To(Equal([]string{whisker.WhiskerBackendLinseedAPIGroup}))
		Expect(cr.Rules[0].Resources).To(Equal([]string{"flows"}))
		Expect(cr.Rules[0].Verbs).To(Equal([]string{"get"}))
		Expect(cr.Rules[1].APIGroups).To(Equal([]string{"authentication.k8s.io"}))
		Expect(cr.Rules[1].Resources).To(Equal([]string{"tokenreviews"}))
		Expect(cr.Rules[1].Verbs).To(Equal([]string{"create"}))
		Expect(cr.Rules[2].APIGroups).To(Equal([]string{"authorization.k8s.io"}))
		Expect(cr.Rules[2].Resources).To(Equal([]string{"subjectaccessreviews"}))
		Expect(cr.Rules[2].Verbs).To(Equal([]string{"create"}))
		// The RBAC calculator reads the cluster's RBAC graph, every namespace and
		// the tier list to work out which flows a user may see.
		Expect(cr.Rules[3].APIGroups).To(Equal([]string{"rbac.authorization.k8s.io"}))
		Expect(cr.Rules[3].Resources).To(Equal([]string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"}))
		Expect(cr.Rules[3].Verbs).To(Equal([]string{"get", "list", "watch"}))
		Expect(cr.Rules[4].APIGroups).To(Equal([]string{""}))
		Expect(cr.Rules[4].Resources).To(Equal([]string{"namespaces"}))
		Expect(cr.Rules[4].Verbs).To(Equal([]string{"list"}))
		Expect(cr.Rules[5].APIGroups).To(Equal([]string{"projectcalico.org"}))
		Expect(cr.Rules[5].Resources).To(Equal([]string{"tiers"}))
		Expect(cr.Rules[5].Verbs).To(Equal([]string{"list"}))

		crb, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, whisker.WhiskerBackendClusterRoleName, "")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(crb.RoleRef.Name).To(Equal(whisker.WhiskerBackendClusterRoleName))
		Expect(crb.Subjects).To(HaveLen(1))
		Expect(crb.Subjects[0].Name).To(Equal(whisker.WhiskerServiceAccountName))
		Expect(crb.Subjects[0].Namespace).To(Equal(whisker.WhiskerNamespace))
	})

	It("should render the backend Service and manager ingress for enterprise variant", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.CalicoEnterprise,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		// Voltron dials this Service to serve the manager UI's /whisker-backend
		// requests; it fronts only the backend container.
		svc, err := rtest.GetResourceOfType[*corev1.Service](objsToCreate, whisker.WhiskerBackendServiceName, whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(svc.Spec.Ports).To(ConsistOf(corev1.ServicePort{
			Port:       whisker.WhiskerBackendServicePort,
			TargetPort: intstr.FromInt(whisker.WhiskerBackendTargetPort),
		}))
		Expect(svc.Spec.Selector).To(Equal(map[string]string{"k8s-app": whisker.WhiskerDeploymentName}))

		// The UI Service and nginx config are OSS-only.
		_, err = rtest.GetResourceOfType[*corev1.Service](objsToCreate, whisker.WhiskerName, whisker.WhiskerNamespace)
		Expect(err).Should(HaveOccurred())

		np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, whisker.WhiskerPolicyName, whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(np.Spec.Ingress).To(HaveLen(1))
		Expect(np.Spec.Ingress[0].Source).To(Equal(networkpolicy.DefaultHelper().ManagerSourceEntityRule()))
		Expect(np.Spec.Ingress[0].Destination.Ports).To(Equal(networkpolicy.Ports(whisker.WhiskerBackendTargetPort)))
	})

	It("should not render Linseed RBAC for Calico variant", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerKeyPair:        defaultWhiskerKeyPair,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		_, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, whisker.WhiskerBackendClusterRoleName, "")
		Expect(err).Should(HaveOccurred())
		_, err = rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, whisker.WhiskerBackendClusterRoleName, "")
		Expect(err).Should(HaveOccurred())
	})

	It("should render network policy with Linseed egress for enterprise variant", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.CalicoEnterprise,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		np, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, whisker.WhiskerPolicyName, whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(np.Spec.Egress).To(HaveLen(3))
		Expect(np.Spec.Egress[0].Destination).To(Equal(networkpolicy.DefaultHelper().LinseedEntityRule()))
		Expect(np.Spec.Egress[1].Destination).To(Equal(networkpolicy.KubeAPIServerEntityRule))
	})

	It("should generate an IPv4-only NGINX configuration", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerKeyPair:        defaultWhiskerKeyPair,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			ClusterID:             "test-cluster-id",
			CalicoVersion:         "test-calico-version",
			ClusterType:           "test-cluster-type",
			ClusterDomain:         "cluster.domain",
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		config, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "whisker-nginx-config", whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())

		actual, ok := config.Data["default.conf"]
		Expect(ok).To(BeTrue(), "expected default.conf to be present in config map")
		Expect(actual).To(Equal(whisker.NginxConfigV4))
	})

	It("should generate a dual-stack NGINX configuration", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					NodeAddressAutodetectionV6: &operatorv1.NodeAddressAutodetection{
						FirstFound: ptr.To(true),
					},
				},
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerKeyPair:        defaultWhiskerKeyPair,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			ClusterID:             "test-cluster-id",
			CalicoVersion:         "test-calico-version",
			ClusterType:           "test-cluster-type",
			ClusterDomain:         "cluster.domain",
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		config, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "whisker-nginx-config", whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())

		actual, ok := config.Data["default.conf"]
		Expect(ok).To(BeTrue(), "expected default.conf to be present in config map")
		Expect(actual).To(Equal(whisker.NginxConfigDual))
	})

	It("should add a gateway ingress rule to the NetworkPolicy when the ingress gateway is configured", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
			},
			TrustedCertBundle:       defaultTrustedCertBundle,
			WhiskerKeyPair:          defaultWhiskerKeyPair,
			WhiskerBackendKeyPair:   defaultTLSKeyPair,
			Whisker:                 &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
			IngressGatewayNamespace: "gateway-ns",
		}
		objsToCreate, _ := whisker.Whisker(cfg).Objects()
		var policy *v3.NetworkPolicy
		for _, obj := range objsToCreate {
			if p, ok := obj.(*v3.NetworkPolicy); ok && p.Name == whisker.WhiskerPolicyName {
				policy = p
			}
		}
		Expect(policy).NotTo(BeNil())
		Expect(policy.Spec.Ingress).To(HaveLen(1))
		rule := policy.Spec.Ingress[0]
		// kubernetes.io/metadata.name, not projectcalico.org/name: the latter is
		// applied by Calico's namespace controller, which does not run on every
		// dataplane (see #5151).
		Expect(rule.Source.NamespaceSelector).To(Equal("kubernetes.io/metadata.name == 'gateway-ns'"))
		Expect(rule.Source.Selector).To(Equal("gateway.envoyproxy.io/owning-gateway-name == 'calico-whisker-gateway'"))
		Expect(rule.Destination.Ports).To(Equal(networkpolicy.Ports(uint16(whisker.WhiskerServicePort))))

		// Without the gateway, Whisker stays deny-all.
		cfg.IngressGatewayNamespace = ""
		objsToCreate, _ = whisker.Whisker(cfg).Objects()
		for _, obj := range objsToCreate {
			if p, ok := obj.(*v3.NetworkPolicy); ok && p.Name == whisker.WhiskerPolicyName {
				Expect(p.Spec.Ingress).To(BeEmpty())
			}
		}
	})

	It("should render a service with HTTPS port", func() {
		cfg := &whisker.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderGKE,
				Variant:            operatorv1.Calico,
			},
			TrustedCertBundle:     defaultTrustedCertBundle,
			WhiskerKeyPair:        defaultWhiskerKeyPair,
			WhiskerBackendKeyPair: defaultTLSKeyPair,
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		}
		component := whisker.Whisker(cfg)
		objsToCreate, _ := component.Objects()

		svc, err := rtest.GetResourceOfType[*corev1.Service](objsToCreate, "whisker", whisker.WhiskerNamespace)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(svc.Spec.Ports).To(HaveLen(1))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(whisker.WhiskerServicePort)))
	})

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
		whiskerResources := &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
		}
		whiskerbackendResources := &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("11Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("11Gi"),
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

		overrides := &operatorv1.WhiskerDeployment{
			Spec: &operatorv1.WhiskerDeploymentSpec{
				Template: &operatorv1.WhiskerDeploymentPodTemplateSpec{
					Metadata: &operatorv1.Metadata{
						Labels:      podLabels,
						Annotations: podAnnotations,
					},
					Spec: &operatorv1.WhiskerDeploymentPodSpec{
						Affinity: affinity,
						Containers: []operatorv1.WhiskerDeploymentContainer{
							{
								Name:      "whisker",
								Resources: whiskerResources,
							},
							{
								Name:      "whisker-backend",
								Resources: whiskerbackendResources,
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

		deployment, err := GetOverriddenWhiskerDeployment(overrides)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(deployment.Spec.Template.ObjectMeta.Labels).To(Equal(podLabels))
		// Override annotations are merged on top of the rendered key pair hash annotations.
		expectedAnnotations := map[string]string{
			defaultWhiskerKeyPair.HashAnnotationKey(): defaultWhiskerKeyPair.HashAnnotationValue(),
			defaultTLSKeyPair.HashAnnotationKey():     defaultTLSKeyPair.HashAnnotationValue(),
		}
		for k, v := range podAnnotations {
			expectedAnnotations[k] = v
		}
		Expect(deployment.Spec.Template.ObjectMeta.Annotations).To(Equal(expectedAnnotations))
		Expect(deployment.Spec.Template.Spec.Affinity).To(Equal(affinity))
		Expect(deployment.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologyConstraints))
		Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
		Expect(deployment.Spec.Template.Spec.Tolerations).To(Equal(tolerations))
		Expect(deployment.Spec.Template.Spec.PriorityClassName).To(Equal(priorityClassName))
		Expect(deployment.Spec.Template.Spec.Containers[0].Resources).To(Equal(*whiskerResources))
		Expect(deployment.Spec.Template.Spec.Containers[1].Resources).To(Equal(*whiskerbackendResources))
	})
})

func GetOverriddenWhiskerDeployment(overrides *operatorv1.WhiskerDeployment) (*appsv1.Deployment, error) {
	component := whisker.Whisker(&whisker.Configuration{
		Installation: &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderGKE,
			Variant:            operatorv1.Calico,
		},
		TrustedCertBundle:     defaultTrustedCertBundle,
		WhiskerKeyPair:        defaultWhiskerKeyPair,
		WhiskerBackendKeyPair: defaultTLSKeyPair,
		Whisker: &operatorv1.Whisker{
			Spec: operatorv1.WhiskerSpec{
				WhiskerDeployment: overrides,
				Notifications:     ptr.To(operatorv1.Enabled),
			},
		},
	})

	objsToCreate, _ := component.Objects()
	return rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, whisker.WhiskerName, whisker.WhiskerNamespace)
}
