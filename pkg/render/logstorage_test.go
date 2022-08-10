// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

package render_test

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/render/testutils"

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type resourceTestObj struct {
	name string
	ns   string
	typ  runtime.Object
	f    func(resource runtime.Object)
}

var _ = Describe("Elasticsearch rendering tests", func() {
	// Setup shared policies utilities that require Ginkgo context.
	var (
		expectedOperatorPolicy             = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elastic-operator.json")
		expectedOperatorPolicyForOpenshift = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elastic-operator_ocp.json")
		expectedESPolicy                   = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elasticsearch.json")
		expectedESPolicyForOpenshift       = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elasticsearch_ocp.json")
		expectedESInternalPolicy           = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elasticsearch-internal.json")
		expectedKibanaPolicy               = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/kibana.json")
		expectedKibanaPolicyForOpenshift   = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/kibana_ocp.json")
		expectedCuratorPolicy              = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elastic-curator.json")
		expectedCuratorPolicyForOpenshift  = testutils.GetExpectedPolicyFromFile("testutils/expected_policies/elastic-curator_ocp.json")
	)
	getExpectedPolicy := func(policyName types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
		if scenario.ManagedCluster {
			return nil
		}

		switch policyName.Name {
		case "allow-tigera.elasticsearch-access":
			return testutils.SelectPolicyByProvider(scenario, expectedESPolicy, expectedESPolicyForOpenshift)

		case "allow-tigera.allow-elastic-curator":
			return testutils.SelectPolicyByProvider(scenario, expectedCuratorPolicy, expectedCuratorPolicyForOpenshift)

		case "allow-tigera.kibana-access":
			return testutils.SelectPolicyByProvider(scenario, expectedKibanaPolicy, expectedKibanaPolicyForOpenshift)

		case "allow-tigera.elastic-operator-access":
			return testutils.SelectPolicyByProvider(scenario, expectedOperatorPolicy, expectedOperatorPolicyForOpenshift)

		case "allow-tigera.elasticsearch-internal":
			return expectedESInternalPolicy

		default:
			return nil
		}
	}

	Context("Standalone cluster type", func() {
		var cfg *render.ElasticsearchConfiguration
		replicas := int32(1)
		retention := int32(1)

		BeforeEach(func() {
			logStorage := &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{
					Nodes: &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: nil,
					},
					Indices: &operatorv1.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
						DNSLogs:           &retention,
						BGPLogs:           &retention,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}

			esConfig := relasticsearch.NewClusterConfig("cluster", 1, 1, 1)

			elasticsearchKeyPair, kibanaKeyPair, trustedBundle := getTLS(installation)
			cfg = &render.ElasticsearchConfiguration{
				LogStorage:           logStorage,
				Installation:         installation,
				ClusterConfig:        esConfig,
				ElasticsearchKeyPair: elasticsearchKeyPair,
				KibanaKeyPair:        kibanaKeyPair,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
				TrustedBundle:      trustedBundle,
				UsePSP:             true,
			}
		})

		It("should not panic if an empty spec is provided", func() {
			// Override with an instance that has no spec.
			cfg.LogStorage = &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{},
			}

			component := render.LogStorage(cfg)

			// Render the objects and make sure we don't panic!
			_, _ = component.Objects()
		})

		Context("Initial creation", func() {
			It("should render properly when PSP is not supported by the cluster", func() {
				cfg.UsePSP = false
				component := render.LogStorage(cfg)
				Expect(component.ResolveImages(nil)).To(BeNil())
				resources, _ := component.Objects()

				// Should not contain any PodSecurityPolicies
				for _, r := range resources {
					Expect(r.GetObjectKind()).NotTo(Equal("PodSecurityPolicy"))
				}
			})

			It("should render an elasticsearchComponent", func() {
				expectedCreateResources := []resourceTestObj{
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{render.ECKOperatorPolicyName, render.ECKOperatorNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{render.ElasticsearchPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ElasticsearchInternalPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{render.KibanaPolicyName, render.KibanaNamespace, &v3.NetworkPolicy{}, nil},
					{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.KibanaNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-kibana", render.KibanaNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				}

				component := render.LogStorage(cfg)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})

				// Check the namespaces.
				namespace := rtest.GetResource(createResources, "tigera-eck-operator", "", "", "v1", "Namespace").(*corev1.Namespace)
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("baseline"))
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

				namespace = rtest.GetResource(createResources, "tigera-elasticsearch", "", "", "v1", "Namespace").(*corev1.Namespace)
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("privileged"))
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

				namespace = rtest.GetResource(createResources, "tigera-kibana", "", "", "v1", "Namespace").(*corev1.Namespace)
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("baseline"))
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

				resultES := rtest.GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)

				// There are no node selectors in the LogStorage CR, so we expect no node selectors in the Elasticsearch CR.
				nodeSet := resultES.Spec.NodeSets[0]
				Expect(nodeSet.PodTemplate.Spec.NodeSelector).To(BeEmpty())

				// Verify that an initContainer is added
				initContainers := resultES.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
				Expect(len(initContainers)).To(Equal(2))
				Expect(initContainers[0].Name).To(Equal("elastic-internal-init-os-settings"))
				Expect(initContainers[1].Name).To(Equal("elastic-internal-init-log-selinux-context"))

				// Verify that the default container limits/requests are set.
				esContainer := resultES.Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
				limits := esContainer.Resources.Limits
				resources := esContainer.Resources.Requests

				Expect(limits.Cpu().String()).To(Equal("1"))
				Expect(limits.Memory().String()).To(Equal("4Gi"))
				Expect(resources.Cpu().String()).To(Equal("250m"))
				Expect(resources.Memory().String()).To(Equal("4Gi"))
				Expect(esContainer.Env[0].Value).To(Equal("-Xms2G -Xmx2G"))

				// Check that the expected config made it's way to the Elastic CR
				Expect(nodeSet.Config.Data).Should(Equal(map[string]interface{}{
					"node.master":                 "true",
					"node.data":                   "true",
					"node.ingest":                 "true",
					"cluster.max_shards_per_node": 10000,
				}))
				resultECK := rtest.GetResource(createResources, render.ECKOperatorName, render.ECKOperatorNamespace,
					"apps", "v1", "StatefulSet").(*appsv1.StatefulSet)
				Expect(resultECK.Spec.Template.Spec.Containers[0].Args).To(ConsistOf([]string{
					"manager",
					"--namespaces=tigera-elasticsearch,tigera-kibana",
					"--log-verbosity=0",
					"--metrics-port=0",
					"--container-registry=testregistry.com/",
					"--max-concurrent-reconciles=3",
					"--ca-cert-validity=8760h",
					"--ca-cert-rotate-before=24h",
					"--cert-validity=8760h",
					"--cert-rotate-before=24h",
					"--enable-webhook=false",
					"--manage-webhook-certs=false",
				}))

				kb := rtest.GetResource(createResources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana")
				Expect(kb).NotTo(BeNil())
				kibana := kb.(*kbv1.Kibana)
				Expect(*kibana.Spec.PodTemplate.Spec.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
				Expect(*kibana.Spec.PodTemplate.Spec.SecurityContext.RunAsNonRoot).To(BeTrue())
				Expect(*kibana.Spec.PodTemplate.Spec.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			})

			It("should render an elasticsearchComponent and delete the Elasticsearch and Kibana ExternalService", func() {
				expectedCreateResources := []resourceTestObj{
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{render.ECKOperatorPolicyName, render.ECKOperatorNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{render.ElasticsearchPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ElasticsearchInternalPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{render.KibanaPolicyName, render.KibanaNamespace, &v3.NetworkPolicy{}, nil},
					{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.KibanaNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-kibana", render.KibanaNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				}

				expectedDeleteResources := []resourceTestObj{
					{render.ElasticsearchServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
					{render.KibanaServiceName, render.KibanaNamespace, &corev1.Service{}, nil},
				}

				cfg.ESService = &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName},
				}
				cfg.KbService = &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: render.KibanaServiceName, Namespace: render.KibanaNamespace},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName},
				}
				cfg.ElasticLicenseType = render.ElasticsearchLicenseTypeBasic

				component := render.LogStorage(cfg)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, expectedDeleteResources)
			})

			It("should render an elasticsearchComponent with certificate management enabled", func() {
				cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{
					CACert:             cfg.ElasticsearchKeyPair.GetCertificatePEM(),
					SignerName:         "my signer name",
					SignatureAlgorithm: "ECDSAWithSHA256",
					KeyAlgorithm:       "ECDSAWithCurve521",
				}

				cfg.ElasticsearchKeyPair, cfg.KibanaKeyPair, cfg.TrustedBundle = getTLS(cfg.Installation)

				expectedCreateResources := []resourceTestObj{
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{render.ECKOperatorPolicyName, render.ECKOperatorNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{render.ElasticsearchPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ElasticsearchInternalPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{render.KibanaPolicyName, render.KibanaNamespace, &v3.NetworkPolicy{}, nil},
					{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.KibanaNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-kibana", render.KibanaNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
					// Certificate management comes with two additional cluster role bindings:
					{relasticsearch.UnusedCertSecret, common.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchInternalCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
				}
				cfg.UnusedTLSSecret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.UnusedCertSecret, Namespace: common.OperatorNamespace()},
				}
				component := render.LogStorage(cfg)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})

				resultES := rtest.GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)

				initContainers := resultES.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
				Expect(initContainers).To(HaveLen(5))
				compareInitContainer := func(ic corev1.Container, expectedName string, expectedVolumes []corev1.VolumeMount) {
					Expect(ic.Name).To(Equal(expectedName))
					Expect(ic.VolumeMounts).To(HaveLen(len(expectedVolumes)))
					for i, vm := range ic.VolumeMounts {
						Expect(vm.Name).To(Equal(expectedVolumes[i].Name))
						Expect(vm.MountPath).To(Equal(expectedVolumes[i].MountPath))
					}
				}
				compareInitContainer(initContainers[0], "elastic-internal-init-os-settings", []corev1.VolumeMount{})
				compareInitContainer(initContainers[1], "elastic-internal-init-filesystem", []corev1.VolumeMount{
					{Name: "elastic-internal-transport-certificates", MountPath: "/csr"},
				})
				compareInitContainer(initContainers[2], "key-cert-elastic", []corev1.VolumeMount{
					{Name: "elastic-internal-http-certificates", MountPath: certificatemanagement.CSRCMountPath},
				})
				compareInitContainer(initContainers[3], "key-cert-elastic-transport", []corev1.VolumeMount{
					{Name: "elastic-internal-transport-certificates", MountPath: certificatemanagement.CSRCMountPath},
				})
				compareInitContainer(initContainers[4], "elastic-internal-init-log-selinux-context", []corev1.VolumeMount{})
			})
		})

		Context("Elasticsearch and Kibana both ready", func() {
			BeforeEach(func() {
				cfg.CuratorSecrets = []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: common.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: common.OperatorNamespace()}},
				}
				cfg.ClusterDomain = dns.DefaultClusterDomain
			})

			It("should render correctly", func() {
				expectedCreateResources := []resourceTestObj{
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{render.ECKOperatorPolicyName, render.ECKOperatorNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{render.ElasticsearchPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ElasticsearchInternalPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{render.KibanaPolicyName, render.KibanaNamespace, &v3.NetworkPolicy{}, nil},
					{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.KibanaNamespace, &v3.NetworkPolicy{}, nil},
					{"tigera-kibana", render.KibanaNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.EsCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.EsCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.EsCuratorName, render.ElasticsearchNamespace, &batchv1beta.CronJob{}, nil},
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				}

				cfg.Provider = operatorv1.ProviderNone
				component := render.LogStorage(cfg)
				createResources, deleteResources := component.Objects()

				cronjob, ok := rtest.GetResource(createResources, "elastic-curator", "tigera-elasticsearch", "batch", "v1", "CronJob").(*batchv1beta.CronJob)
				Expect(ok).To(BeTrue())

				Expect(cronjob.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Env).To(ContainElements([]corev1.EnvVar{
					{Name: "EE_FLOWS_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(1)},
					{Name: "EE_AUDIT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(1)},
					{Name: "EE_SNAPSHOT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(1)},
					{Name: "EE_COMPLIANCE_REPORT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(1)},
					{Name: "EE_DNS_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(1)},
					{Name: "EE_BGP_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(1)},
					{Name: "EE_MAX_TOTAL_STORAGE_PCT", Value: fmt.Sprint(80)},
					{Name: "EE_MAX_LOGS_STORAGE_PCT", Value: fmt.Sprint(70)},
				}))

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})

			Context("allow-tigera rendering", func() {
				policyNames := []types.NamespacedName{
					{Name: "allow-tigera.elasticsearch-access", Namespace: "tigera-elasticsearch"},
					{Name: "allow-tigera.allow-elastic-curator", Namespace: "tigera-elasticsearch"},
					{Name: "allow-tigera.kibana-access", Namespace: "tigera-kibana"},
					{Name: "allow-tigera.elastic-operator-access", Namespace: "tigera-eck-operator"},
					{Name: "allow-tigera.elasticsearch-internal", Namespace: "tigera-elasticsearch"},
				}

				DescribeTable("should render allow-tigera policy",
					func(scenario testutils.AllowTigeraScenario) {
						if scenario.Openshift {
							cfg.Provider = operatorv1.ProviderOpenShift
						} else {
							cfg.Provider = operatorv1.ProviderNone
						}

						component := render.LogStorage(cfg)
						resources, _ := component.Objects()

						for _, policyName := range policyNames {
							policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
							expectedPolicy := getExpectedPolicy(policyName, scenario)
							Expect(policy).To(Equal(expectedPolicy))
						}
					},
					Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
					Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
				)
			})
		})

		Context("Deleting LogStorage", deleteLogStorageTests(nil, nil))

		Context("Updating LogStorage resource", func() {
			It("should create new NodeSet", func() {
				cfg.LogStorage = &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: 1,
							ResourceRequirements: &corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									"cpu":    resource.MustParse("1"),
									"memory": resource.MustParse("150Mi"),
								},
								Requests: corev1.ResourceList{
									"cpu":     resource.MustParse("1"),
									"memory":  resource.MustParse("150Mi"),
									"storage": resource.MustParse("10Gi"),
								},
							},
						},
					},
				}
				cfg.Elasticsearch = &esv1.Elasticsearch{}

				component := render.LogStorage(cfg)

				createResources, _ := component.Objects()

				oldNodeSetName := rtest.GetResource(createResources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch).Spec.NodeSets[0].Name

				// update resource requirements
				cfg.LogStorage.Spec.Nodes.ResourceRequirements = &corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("150Mi"),
					},
					Requests: corev1.ResourceList{
						"cpu":     resource.MustParse("1"),
						"memory":  resource.MustParse("2Gi"),
						"storage": resource.MustParse("5Gi"),
					},
				}

				updatedComponent := render.LogStorage(cfg)

				updatedResources, _ := updatedComponent.Objects()

				newNodeName := rtest.GetResource(updatedResources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch).Spec.NodeSets[0].Name
				Expect(newNodeName).NotTo(Equal(oldNodeSetName))
			})
		})

		It("should render DataNodeSelectors defined in the LogStorage CR", func() {
			cfg.LogStorage.Spec.DataNodeSelector = map[string]string{
				"k1": "v1",
				"k2": "v2",
			}
			component := render.LogStorage(cfg)

			// Verify that the node selectors are passed into the Elasticsearch pod spec.
			createResources, _ := component.Objects()
			nodeSelectors := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.NodeSelector
			Expect(nodeSelectors["k1"]).To(Equal("v1"))
			Expect(nodeSelectors["k2"]).To(Equal("v2"))
		})

		It("should configures Kibana publicBaseUrl when BaseURL is specified", func() {
			cfg.ElasticLicenseType = render.ElasticsearchLicenseTypeBasic
			cfg.BaseURL = "https://test.domain.com"

			component := render.LogStorage(cfg)

			createResources, _ := component.Objects()
			kb := rtest.GetResource(createResources, render.KibanaName, render.KibanaNamespace, "kibana.k8s.elastic.co", "v1", "Kibana")
			Expect(kb).ShouldNot(BeNil())
			kibana := kb.(*kbv1.Kibana)
			x := kibana.Spec.Config.Data["server"].(map[string]interface{})
			Expect(x["publicBaseUrl"]).To(Equal("https://test.domain.com/tigera-kibana"))
		})

		Context("ECKOperator memory requests/limits", func() {
			When("LogStorage Spec contains an entry for ECKOperator in ComponentResources", func() {
				It("should set matching memory requests/limits in the elastic-operator StatefulSet.Spec manager container", func() {
					limits := corev1.ResourceList{}
					requests := corev1.ResourceList{}
					limits[corev1.ResourceMemory] = resource.MustParse("512Mi")
					requests[corev1.ResourceMemory] = resource.MustParse("512Mi")
					cfg.LogStorage.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
						{
							ComponentName: operatorv1.ComponentNameECKOperator,
							ResourceRequirements: &corev1.ResourceRequirements{
								Limits:   limits,
								Requests: requests,
							},
						},
					}

					limits[corev1.ResourceCPU] = resource.MustParse("1")
					requests[corev1.ResourceCPU] = resource.MustParse("100m")
					expectedResourcesRequirements := corev1.ResourceRequirements{
						Limits:   limits,
						Requests: requests,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()

					statefulSet := rtest.GetResource(createResources, render.ECKOperatorName, render.ECKOperatorNamespace, "apps", "v1", "StatefulSet").(*appsv1.StatefulSet)
					Expect(statefulSet).Should(Not(BeNil()))
					Expect(statefulSet.Spec.Template.Spec.Containers).ToNot(BeEmpty())
					for _, container := range statefulSet.Spec.Template.Spec.Containers {
						if container.Name == "manager" {
							Expect(container).NotTo(BeNil())
							Expect(container.Resources).To(Equal(expectedResourcesRequirements))
							break
						}
					}
				})
			})
		})
		It("should not render kibana if FIPS mode is enabled", func() {
			fipsEnabled := operatorv1.FIPSModeEnabled
			cfg.Installation.FIPSMode = &fipsEnabled
			cfg.LogStorage.Spec.Nodes.ResourceRequirements = &corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":    resource.MustParse("1"),
					"memory": resource.MustParse("150Mi"),
				},
				Requests: corev1.ResourceList{
					"cpu":     resource.MustParse("1"),
					"memory":  resource.MustParse("150Mi"),
					"storage": resource.MustParse("10Gi"),
				},
			}

			cfg.ApplyTrial = true
			cfg.KeyStoreSecret = render.CreateElasticsearchKeystoreSecret()
			expectedCreateResources := []resourceTestObj{
				{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
				{render.ECKOperatorPolicyName, render.ECKOperatorNamespace, &v3.NetworkPolicy{}, nil},
				{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
				{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
				{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
				{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
				{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
				{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
				{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
				{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
				{render.ECKEnterpriseTrial, render.ECKOperatorNamespace, &corev1.Secret{}, nil},
				{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
				{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
				{render.ElasticsearchPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
				{render.ElasticsearchInternalPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
				{networkpolicy.TigeraComponentDefaultDenyPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
				{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
				{relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), &corev1.ConfigMap{}, nil},
				{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
				{render.ElasticsearchKeystoreSecret, common.OperatorNamespace(), &corev1.Secret{}, nil},
				{render.ElasticsearchKeystoreSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
				{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
			}

			component := render.LogStorage(cfg)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, []resourceTestObj{
				{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
				{render.EsCuratorName, render.ElasticsearchNamespace, &batchv1beta.CronJob{}, nil},
			})

			es := getElasticsearch(createResources)
			esContainer := es.Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
			initContainers := es.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
			Expect(esContainer.Env).Should(ContainElement(corev1.EnvVar{
				Name:  "ES_JAVA_OPTS",
				Value: fmt.Sprintf("-Xms75M -Xmx75M --module-path /usr/share/bc-fips/ -Djavax.net.ssl.trustStore=/usr/share/elasticsearch/config/cacerts.bcfks-Djavax.net.ssl.trustStoreType=BCFKS -Djavax.net.ssl.trustStorePassword=${KEYSTORE_PASSWORD} -Dorg.bouncycastle.fips.approved_only=true"),
			}))
			Expect(initContainers).To(HaveLen(3))
			Expect(initContainers[1].Name).To(Equal("elastic-internal-init-jvm-keystore"))
		})
	})

	Context("Managed cluster", func() {
		var cfg *render.ElasticsearchConfiguration
		var managementClusterConnection *operatorv1.ManagementClusterConnection

		BeforeEach(func() {
			replicas := int32(1)
			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}

			managementClusterConnection = &operatorv1.ManagementClusterConnection{}

			cfg = &render.ElasticsearchConfiguration{
				Installation:                installation,
				ManagementClusterConnection: managementClusterConnection,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
				UsePSP:             true,
			}
		})
		Context("Initial creation", func() {
			It("creates Managed cluster logstorage components", func() {
				expectedCreateResources := []resourceTestObj{
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{render.ESGatewayServiceName, render.ElasticsearchNamespace, &corev1.Service{}, func(resource runtime.Object) {
						svc := resource.(*corev1.Service)

						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
						Expect(svc.Spec.ExternalName).Should(Equal(fmt.Sprintf("%s.%s.svc.%s", render.GuardianServiceName, render.GuardianNamespace, dns.DefaultClusterDomain)))
					}},
				}

				component := render.LogStorage(cfg)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})
		})
		Context("Deleting LogStorage", deleteLogStorageTests(nil, managementClusterConnection))
		Context("allow-tigera rendering", func() {
			policyNames := []types.NamespacedName{
				{Name: "allow-tigera.elasticsearch-access", Namespace: "tigera-elasticsearch"},
				{Name: "allow-tigera.allow-elastic-curator", Namespace: "tigera-elasticsearch"},
				{Name: "allow-tigera.kibana-access", Namespace: "tigera-kibana"},
				{Name: "allow-tigera.elastic-operator-access", Namespace: "tigera-eck-operator"},
				{Name: "allow-tigera.elasticsearch-internal", Namespace: "tigera-elasticsearch"},
			}

			DescribeTable("should render allow-tigera policy",
				func(scenario testutils.AllowTigeraScenario) {
					if scenario.Openshift {
						cfg.Provider = operatorv1.ProviderOpenShift
					} else {
						cfg.Provider = operatorv1.ProviderNone
					}

					component := render.LogStorage(cfg)
					resources, _ := component.Objects()

					for _, policyName := range policyNames {
						policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
						expectedPolicy := getExpectedPolicy(policyName, scenario)
						Expect(policy).To(Equal(expectedPolicy))
					}
				},
				Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}),
				Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}),
			)
		})
	})

	Context("NodeSet configuration", func() {
		var cfg *render.ElasticsearchConfiguration
		replicas, retention := int32(1), int32(1)

		BeforeEach(func() {
			logStorage := &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{
					Indices: &operatorv1.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
						DNSLogs:           &retention,
						BGPLogs:           &retention,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			esConfig := relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
			elasticsearchKeyPair, kibanaKeyPair, trustedBundle := getTLS(installation)
			cfg = &render.ElasticsearchConfiguration{
				LogStorage:           logStorage,
				Installation:         installation,
				ClusterConfig:        esConfig,
				ElasticsearchKeyPair: elasticsearchKeyPair,
				KibanaKeyPair:        kibanaKeyPair,
				TrustedBundle:        trustedBundle,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
				UsePSP:             true,
			}
		})
		Context("Node distribution", func() {
			When("the number of Nodes and NodeSets is 3", func() {
				It("creates 3 1 Node NodeSet", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 3,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(1)))
					}
				})
			})
			When("the number of Nodes is 2 and the number of NodeSets is 3", func() {
				It("creates 2 1 Node NodeSets", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 2,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(1)))
					}
				})
			})
			When("the number of Nodes is 6 and the number of NodeSets is 3", func() {
				It("creates 3 2 Node NodeSets", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 6,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))
					for _, nodeSet := range nodeSets {
						Expect(nodeSet.Count).Should(Equal(int32(2)))
					}
				})
			})
			When("the number of Nodes is 5 and the number of NodeSets is 6", func() {
				It("creates 2 2 Node NodeSets and 1 1 Node NodeSet", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 5,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(3))

					Expect(nodeSets[0].Count).Should(Equal(int32(2)))
					Expect(nodeSets[1].Count).Should(Equal(int32(2)))
					Expect(nodeSets[2].Count).Should(Equal(int32(1)))
				})
			})
		})
		Context("Node Resource", func() {
			When("the ResourceRequirements is set", func() {
				defaultLimitCpu := "1"
				defaultLimitMemory := "4Gi"
				defaultRequestsCpu := "250m"
				defaultRequestsMemory := "4Gi"
				It("sets memory and cpu requirements in pod template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse("5"),
							"memory": resource.MustParse("2Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("500m"),
							"memory": resource.MustParse("2Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pod := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
					Expect(pod.Resources).Should(Equal(res))
					Expect(pod.Env[0].Value).To(Equal("-Xms1G -Xmx1G"))
				})
				It("sets default memory and cpu requirements in pod template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"memory": resource.MustParse("10Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu": resource.MustParse(defaultRequestsCpu),
						},
					}
					expectedRes := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultLimitCpu),
							"memory": resource.MustParse("10Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultRequestsCpu),
							"memory": resource.MustParse(defaultRequestsMemory),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pod := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
					Expect(pod.Resources).Should(Equal(expectedRes))
					Expect(pod.Env[0].Value).To(Equal("-Xms2G -Xmx2G"))
				})
				It("sets value of Limits to user's Requests when user's Limits is not set and default Limits is lesser than Requests", func() {
					res := corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse("1Gi"),
						},
					}
					expectedRes := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse(defaultLimitMemory),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse("1Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pod := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
					Expect(pod.Resources).Should(Equal(expectedRes))
					Expect(pod.Env[0].Value).To(Equal("-Xms512M -Xmx512M"))
				})
				It("sets value of Requests to user's Limits when user's Requests is not set and default Requests is greater than Limits", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"memory": resource.MustParse("2Gi"),
						},
					}
					expectedRes := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultLimitCpu),
							"memory": resource.MustParse("2Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultRequestsCpu),
							"memory": resource.MustParse("2Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					podResource := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0].Resources
					Expect(podResource).Should(Equal(expectedRes))
				})
				It("sets storage requirements in pvc template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"storage": resource.MustParse("16Gi"),
						},
						Requests: corev1.ResourceList{
							"storage": resource.MustParse("8Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pvcResource := getElasticsearch(createResources).Spec.NodeSets[0].VolumeClaimTemplates[0].Spec.Resources
					Expect(pvcResource).Should(Equal(res))
				})
				It("sets storage value of Requests to user's Limits when user's Requests is not set and default Requests is greater than Limits in pvc template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"storage": resource.MustParse("8Gi"),
						},
					}
					expected := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"storage": resource.MustParse("8Gi"),
						},
						Requests: corev1.ResourceList{
							"storage": resource.MustParse("8Gi"),
						},
					}
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					pvcResource := getElasticsearch(createResources).Spec.NodeSets[0].VolumeClaimTemplates[0].Spec.Resources
					Expect(pvcResource).Should(Equal(expected))
				})
			})
		})
		Context("Node selection", func() {
			When("NodeSets is set but empty", func() {
				It("returns the default NodeSet", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:    2,
						NodeSets: []operatorv1.NodeSet{},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(1))
				})
			})
			When("there is a single selection attribute for a NodeSet", func() {
				It("sets the Node Affinity Elasticsearch cluster awareness attributes with the single selection attribute", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 2,
						NodeSets: []operatorv1.NodeSet{
							{
								SelectionAttributes: []operatorv1.NodeSetSelectionAttribute{{
									Name:      "zone",
									NodeLabel: "failure-domain.beta.kubernetes.io/zone",
									Value:     "us-west-2a",
								}},
							},
							{
								SelectionAttributes: []operatorv1.NodeSetSelectionAttribute{{
									Name:      "zone",
									NodeLabel: "failure-domain.beta.kubernetes.io/zone",
									Value:     "us-west-2b",
								}},
							},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					Expect(nodeSets[0].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{{
									Key:      "failure-domain.beta.kubernetes.io/zone",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"us-west-2a"},
								}},
							}},
						},
					}))
					Expect(nodeSets[0].Config.Data).Should(Equal(map[string]interface{}{
						"node.master":                 "true",
						"node.data":                   "true",
						"node.ingest":                 "true",
						"cluster.max_shards_per_node": 10000,
						"node.attr.zone":              "us-west-2a",
						"cluster.routing.allocation.awareness.attributes": "zone",
					}))

					Expect(nodeSets[1].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{{
									Key:      "failure-domain.beta.kubernetes.io/zone",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"us-west-2b"},
								}},
							}},
						},
					}))
					Expect(nodeSets[1].Config.Data).Should(Equal(map[string]interface{}{
						"node.master":                 "true",
						"node.data":                   "true",
						"node.ingest":                 "true",
						"cluster.max_shards_per_node": 10000,
						"node.attr.zone":              "us-west-2b",
						"cluster.routing.allocation.awareness.attributes": "zone",
					}))
				})
			})
			When("there are multiple selection attributes for a NodeSet", func() {
				It("combines to attributes for the Node Affinity and Elasticsearch cluster awareness attributes", func() {
					cfg.LogStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 2,
						NodeSets: []operatorv1.NodeSet{
							{
								SelectionAttributes: []operatorv1.NodeSetSelectionAttribute{
									{
										Name:      "zone",
										NodeLabel: "failure-domain.beta.kubernetes.io/zone",
										Value:     "us-west-2a",
									},
									{
										Name:      "rack",
										NodeLabel: "some-rack-label.kubernetes.io/rack",
										Value:     "rack1",
									},
								},
							},
							{
								SelectionAttributes: []operatorv1.NodeSetSelectionAttribute{
									{
										Name:      "zone",
										NodeLabel: "failure-domain.beta.kubernetes.io/zone",
										Value:     "us-west-2b",
									},
									{
										Name:      "rack",
										NodeLabel: "some-rack-label.kubernetes.io/rack",
										Value:     "rack1",
									},
								},
							},
						},
					}

					component := render.LogStorage(cfg)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(2))
					Expect(nodeSets[0].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "failure-domain.beta.kubernetes.io/zone",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"us-west-2a"},
									},
									{
										Key:      "some-rack-label.kubernetes.io/rack",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"rack1"},
									},
								},
							}},
						},
					}))
					Expect(nodeSets[0].Config.Data).Should(Equal(map[string]interface{}{
						"node.master":                 "true",
						"node.data":                   "true",
						"node.ingest":                 "true",
						"cluster.max_shards_per_node": 10000,
						"node.attr.zone":              "us-west-2a",
						"node.attr.rack":              "rack1",
						"cluster.routing.allocation.awareness.attributes": "zone,rack",
					}))

					Expect(nodeSets[1].PodTemplate.Spec.Affinity.NodeAffinity).Should(Equal(&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{
								{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{
											Key:      "failure-domain.beta.kubernetes.io/zone",
											Operator: corev1.NodeSelectorOpIn,
											Values:   []string{"us-west-2b"},
										},
										{
											Key:      "some-rack-label.kubernetes.io/rack",
											Operator: corev1.NodeSelectorOpIn,
											Values:   []string{"rack1"},
										},
									},
								},
							},
						},
					}))
					Expect(nodeSets[1].Config.Data).Should(Equal(map[string]interface{}{
						"node.master":                 "true",
						"node.data":                   "true",
						"node.ingest":                 "true",
						"cluster.max_shards_per_node": 10000,
						"node.attr.zone":              "us-west-2b",
						"node.attr.rack":              "rack1",
						"cluster.routing.allocation.awareness.attributes": "zone,rack",
					}))
				})
			})
		})
	})

	Context("Kibana high availability", func() {
		var cfg *render.ElasticsearchConfiguration
		replicas := int32(1)
		retention := int32(1)

		BeforeEach(func() {
			logStorage := &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{
					Nodes: &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: nil,
					},
					Indices: &operatorv1.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
						DNSLogs:           &retention,
						BGPLogs:           &retention,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}

			esConfig := relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
			elasticsearchKeyPair, kibanaKeyPair, trustedBundle := getTLS(installation)
			cfg = &render.ElasticsearchConfiguration{
				LogStorage:           logStorage,
				Installation:         installation,
				ClusterConfig:        esConfig,
				ElasticsearchKeyPair: elasticsearchKeyPair,
				KibanaKeyPair:        kibanaKeyPair,
				TrustedBundle:        trustedBundle,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
				UsePSP:             true,
			}
		})

		It("should set count to 1 when ControlPlaneReplicas is nil", func() {
			cfg.Installation.ControlPlaneReplicas = nil
			component := render.LogStorage(cfg)
			resources, _ := component.Objects()

			kibana, ok := rtest.GetResource(resources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
			Expect(ok).To(BeTrue())
			Expect(kibana.Spec.Count).To(Equal(int32(1)))
			Expect(kibana.Spec.PodTemplate.Spec.Affinity).To(BeNil())
		})

		It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
			var replicas int32 = 1
			cfg.Installation.ControlPlaneReplicas = &replicas

			component := render.LogStorage(cfg)
			resources, _ := component.Objects()

			kibana, ok := rtest.GetResource(resources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
			Expect(ok).To(BeTrue())
			Expect(kibana.Spec.PodTemplate.Spec.Affinity).To(BeNil())
		})

		It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
			var replicas int32 = 2
			cfg.Installation.ControlPlaneReplicas = &replicas

			component := render.LogStorage(cfg)
			resources, _ := component.Objects()

			kibana, ok := rtest.GetResource(resources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
			Expect(ok).To(BeTrue())
			Expect(kibana.Spec.PodTemplate.Spec.Affinity).NotTo(BeNil())
			Expect(kibana.Spec.PodTemplate.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-secure", "tigera-kibana")))
		})
	})
})

func getTLS(installation *operatorv1.InstallationSpec) (certificatemanagement.KeyPairInterface, certificatemanagement.KeyPairInterface, certificatemanagement.TrustedBundle) {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain)
	Expect(err).NotTo(HaveOccurred())
	esDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	kbDNSNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, dns.DefaultClusterDomain)
	elasticsearchKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchInternalCertSecret, render.ElasticsearchNamespace, esDNSNames)
	Expect(err).NotTo(HaveOccurred())
	kibanaKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraKibanaCertSecret, common.OperatorNamespace(), kbDNSNames)
	Expect(err).NotTo(HaveOccurred())
	trustedBundle := certificateManager.CreateTrustedBundle(elasticsearchKeyPair, kibanaKeyPair)
	Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
	return elasticsearchKeyPair, kibanaKeyPair, trustedBundle
}

var deleteLogStorageTests = func(managementCluster *operatorv1.ManagementCluster, managementClusterConnection *operatorv1.ManagementClusterConnection) func() {
	return func() {
		var cfg *render.ElasticsearchConfiguration
		replicas := int32(1)
		retention := int32(1)

		BeforeEach(func() {
			t := metav1.Now()

			logStorage := &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "tigera-secure",
					DeletionTimestamp: &t,
				},
				Spec: operatorv1.LogStorageSpec{
					Nodes: &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: nil,
					},
					Indices: &operatorv1.Indices{
						Replicas: &replicas,
					},
					Retention: &operatorv1.Retention{
						Flows:             &retention,
						AuditReports:      &retention,
						Snapshots:         &retention,
						ComplianceReports: &retention,
						DNSLogs:           &retention,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			esConfig := relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
			elasticsearchKeyPair, kibanaKeyPair, trustedBundle := getTLS(installation)

			cfg = &render.ElasticsearchConfiguration{
				LogStorage:                  logStorage,
				Installation:                installation,
				ManagementCluster:           managementCluster,
				ManagementClusterConnection: managementClusterConnection,
				Elasticsearch:               &esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
				Kibana:                      &kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace}},
				ClusterConfig:               esConfig,
				ElasticsearchKeyPair:        elasticsearchKeyPair,
				KibanaKeyPair:               kibanaKeyPair,
				TrustedBundle:               trustedBundle,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				CuratorSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: common.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: common.OperatorNamespace()}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
				UsePSP:             true,
			}
		})
		It("returns Elasticsearch and Kibana CR's to delete and keeps the finalizers on the LogStorage CR", func() {
			expectedCreateResources := []resourceTestObj{}

			expectedDeleteResources := []resourceTestObj{
				{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
				{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
			}

			component := render.LogStorage(cfg)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, expectedDeleteResources)
		})
		It("doesn't return anything to delete when Elasticsearch and Kibana have their deletion times stamps set and the LogStorage finalizers are still set", func() {
			expectedCreateResources := []resourceTestObj{}

			t := metav1.Now()
			cfg.Elasticsearch.DeletionTimestamp = &t
			cfg.Kibana.DeletionTimestamp = &t
			component := render.LogStorage(cfg)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, []resourceTestObj{})
		})
	}
}

func compareResources(resources []client.Object, expectedResources []resourceTestObj) {
	Expect(len(resources)).To(Equal(len(expectedResources)))
	for i, expectedResource := range expectedResources {
		resource := resources[i]
		actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
		actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()

		Expect(actualName).To(Equal(expectedResource.name), fmt.Sprintf("Rendered resource has wrong name (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(actualNS).To(Equal(expectedResource.ns), fmt.Sprintf("Rendered resource has wrong namespace (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(resource).Should(BeAssignableToTypeOf(expectedResource.typ))
		if expectedResource.f != nil {
			expectedResource.f(resource)
		}
	}
}

func getElasticsearch(resources []client.Object) *esv1.Elasticsearch {
	resource := rtest.GetResource(resources, "tigera-secure", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch")
	Expect(resource).ShouldNot(BeNil())

	return resource.(*esv1.Elasticsearch)
}
