// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	"reflect"

	batchv1 "k8s.io/api/batch/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
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
	)
	getExpectedPolicy := func(policyName types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
		if scenario.ManagedCluster {
			return nil
		}

		switch policyName.Name {
		case "allow-tigera.elasticsearch-access":
			return testutils.SelectPolicyByProvider(scenario, expectedESPolicy, expectedESPolicyForOpenshift)

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
					{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
				TrustedBundle:      trustedBundle,
				UsePSP:             true,
				KibanaEnabled:      true,
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
					Expect(reflect.TypeOf(r)).ToNot(Equal(reflect.TypeOf(&policyv1beta1.PodSecurityPolicy{})))
				}
			})

			It("should render an elasticsearchComponent", func() {
				expectedCreateResources := []client.Object{
					// ECK Resources
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ECKOperatorNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ECKOperatorPolicyName, Namespace: render.ECKOperatorNamespace}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: render.ECKOperatorNamespace}},
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator"}},
					&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "elastic-operator", Namespace: render.ECKOperatorNamespace}},
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch"}},
					&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ECKOperatorName}},

					// Kibana resources
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-kibana"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-kibana"}},
					&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-kibana"}},
					&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: render.ECKOperatorName, Namespace: render.ECKOperatorNamespace}},
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPolicyName, Namespace: render.KibanaNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.KibanaNamespace}},
					&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-kibana", Namespace: render.KibanaNamespace}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: render.KibanaNamespace}},
					&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace}},

					// ES resources
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchInternalPolicyName, Namespace: render.ElasticsearchNamespace}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.ElasticsearchNamespace}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: render.ElasticsearchNamespace}},
					&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-elasticsearch", Namespace: render.ElasticsearchNamespace}},
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}},
					&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRole, Namespace: render.ElasticsearchNamespace}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.EsManagerRoleBinding, Namespace: render.ElasticsearchNamespace}},
				}

				component := render.LogStorage(cfg)
				createResources, deleteResources := component.Objects()
				rtest.ExpectResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{
					{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ESCuratorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
				})

				// Check the namespaces.
				namespace := rtest.GetResource(createResources, "tigera-eck-operator", "", "", "v1", "Namespace").(*corev1.Namespace)
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("restricted"))
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
				Expect(resultES.Spec.NodeSets).To(HaveLen(1))
				nodeSet := resultES.Spec.NodeSets[0]
				Expect(nodeSet.PodTemplate.Spec.NodeSelector).To(BeEmpty())

				// Verify that an initContainer is added
				initContainers := resultES.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
				Expect(initContainers).To(HaveLen(1))
				Expect(initContainers[0].Name).To(Equal("elastic-internal-init-os-settings"))
				Expect(*initContainers[0].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
				Expect(*initContainers[0].SecurityContext.Privileged).To(BeTrue())
				Expect(*initContainers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*initContainers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
				Expect(*initContainers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
				Expect(initContainers[0].SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(initContainers[0].SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				// Verify that the default container limits/requests are set.
				Expect(resultES.Spec.NodeSets[0].PodTemplate.Spec.Containers).To(HaveLen(1))
				esContainer := resultES.Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
				Expect(*esContainer.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
				Expect(*esContainer.SecurityContext.Privileged).To(BeFalse())
				Expect(*esContainer.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
				Expect(*esContainer.SecurityContext.RunAsNonRoot).To(BeFalse())
				Expect(*esContainer.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
				Expect(esContainer.SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
						Add:  []corev1.Capability{"SETGID", "SETUID", "SYS_CHROOT"},
					},
				))
				Expect(esContainer.SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				limits := esContainer.Resources.Limits
				resources := esContainer.Resources.Requests

				Expect(limits.Cpu().String()).To(Equal("1"))
				Expect(limits.Memory().String()).To(Equal("4Gi"))
				Expect(resources.Cpu().String()).To(Equal("250m"))
				Expect(resources.Memory().String()).To(Equal("4Gi"))
				Expect(esContainer.Env[0].Value).To(Equal("-Xms2G -Xmx2G"))

				// Check that the expected config made it's way to the Elastic CR
				Expect(nodeSet.Config.Data).Should(Equal(map[string]interface{}{
					"node.master":                     "true",
					"node.data":                       "true",
					"node.ingest":                     "true",
					"cluster.max_shards_per_node":     10000,
					"ingest.geoip.downloader.enabled": false,
				}))
				resultECK := rtest.GetResource(createResources, render.ECKOperatorName, render.ECKOperatorNamespace,
					"apps", "v1", "StatefulSet").(*appsv1.StatefulSet)
				Expect(resultECK.Spec.Template.Spec.Containers).To(HaveLen(1))
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
				Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
				Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
				Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
				Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
				Expect(*resultECK.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
				Expect(resultECK.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(resultECK.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))

				kb := rtest.GetResource(createResources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana")
				Expect(kb).NotTo(BeNil())
				kibana := kb.(*kbv1.Kibana)
				Expect(kibana.Spec.PodTemplate.Spec.Containers).To(HaveLen(1))

				Expect(*kibana.Spec.PodTemplate.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
				Expect(*kibana.Spec.PodTemplate.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
				Expect(*kibana.Spec.PodTemplate.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
				Expect(*kibana.Spec.PodTemplate.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
				Expect(*kibana.Spec.PodTemplate.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
				Expect(kibana.Spec.PodTemplate.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
					&corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				))
				Expect(kibana.Spec.PodTemplate.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
					&corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					}))
				eckRole := rtest.GetResource(createResources, "elastic-operator", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
				Expect(eckRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
					{
						APIGroups: []string{"authorization.k8s.io"},
						Resources: []string{"subjectaccessreviews"},
						Verbs:     []string{"create"},
					},
					{
						APIGroups: []string{"coordination.k8s.io"},
						Resources: []string{"leases"},
						Verbs:     []string{"create"},
					},
					{
						APIGroups:     []string{"coordination.k8s.io"},
						Resources:     []string{"leases"},
						ResourceNames: []string{"elastic-operator-leader"},
						Verbs:         []string{"get", "watch", "update"},
					},
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "endpoints", "events", "persistentvolumeclaims", "secrets", "services", "configmaps", "serviceaccounts"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"apps"},
						Resources: []string{"deployments", "statefulsets", "daemonsets"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"batch"},
						Resources: []string{"cronjobs"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"policy"},
						Resources: []string{"poddisruptionbudgets"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"elasticsearch.k8s.elastic.co"},
						Resources: []string{"elasticsearches", "elasticsearches/status", "elasticsearches/finalizers", "enterpriselicenses", "enterpriselicenses/status"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"autoscaling.k8s.elastic.co"},
						Resources: []string{"elasticsearchautoscalers", "elasticsearchautoscalers/status", "elasticsearchautoscalers/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"kibana.k8s.elastic.co"},
						Resources: []string{"kibanas", "kibanas/status", "kibanas/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"apm.k8s.elastic.co"},
						Resources: []string{"apmservers", "apmservers/status", "apmservers/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"enterprisesearch.k8s.elastic.co"},
						Resources: []string{"enterprisesearches", "enterprisesearches/status", "enterprisesearches/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"beat.k8s.elastic.co"},
						Resources: []string{"beats", "beats/status", "beats/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"agent.k8s.elastic.co"},
						Resources: []string{"agents", "agents/status", "agents/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"maps.k8s.elastic.co"},
						Resources: []string{"elasticmapsservers", "elasticmapsservers/status", "elasticmapsservers/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"stackconfigpolicy.k8s.elastic.co"},
						Resources: []string{"stackconfigpolicies", "stackconfigpolicies/status", "stackconfigpolicies/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"associations.k8s.elastic.co"},
						Resources: []string{"apmserverelasticsearchassociations", "apmserverelasticsearchassociations/status"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"autoscaling.k8s.elastic.co"},
						Resources: []string{"elasticsearchautoscalers", "elasticsearchautoscalers/status", "elasticsearchautoscalers/finalizers"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups:     []string{"policy"},
						Resources:     []string{"podsecuritypolicies"},
						Verbs:         []string{"use"},
						ResourceNames: []string{"elastic-operator"},
					},
				}))
			})

			It("should render an elasticsearchComponent and delete the Elasticsearch and Kibana ExternalService as well as Curator components", func() {
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
					{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ESCuratorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
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
				compareResources(deleteResources, []resourceTestObj{
					{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ESCuratorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
				})

				resultES := rtest.GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)

				initContainers := resultES.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
				Expect(initContainers).To(HaveLen(4))
				compareInitContainer := func(ic corev1.Container, expectedName string, expectedVolumes []corev1.VolumeMount, privileged bool) {
					Expect(ic.Name).To(Equal(expectedName))
					Expect(ic.VolumeMounts).To(HaveLen(len(expectedVolumes)))
					Expect(ic.SecurityContext.Privileged).To(Equal(&privileged))
					for i, vm := range ic.VolumeMounts {
						Expect(vm.Name).To(Equal(expectedVolumes[i].Name))
						Expect(vm.MountPath).To(Equal(expectedVolumes[i].MountPath))
					}
				}
				compareInitContainer(initContainers[0], "elastic-internal-init-os-settings", []corev1.VolumeMount{}, true)
				compareInitContainer(initContainers[1], "elastic-internal-init-filesystem", []corev1.VolumeMount{
					{Name: "elastic-internal-transport-certificates", MountPath: "/csr"},
				}, true)
				compareInitContainer(initContainers[2], "key-cert-elastic", []corev1.VolumeMount{
					{Name: "elastic-internal-http-certificates", MountPath: certificatemanagement.CSRCMountPath},
				}, false)
				compareInitContainer(initContainers[3], "key-cert-elastic-transport", []corev1.VolumeMount{
					{Name: "elastic-internal-transport-certificates", MountPath: certificatemanagement.CSRCMountPath},
				}, false)
			})
		})

		Context("Elasticsearch and Kibana both ready", func() {
			BeforeEach(func() {
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
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				}

				cfg.Provider = operatorv1.ProviderNone
				component := render.LogStorage(cfg)
				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{
					{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.ESCuratorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
				})
			})

			Context("allow-tigera rendering", func() {
				policyNames := []types.NamespacedName{
					{Name: "allow-tigera.elasticsearch-access", Namespace: "tigera-elasticsearch"},
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

		It("should not render kibana when configured not to do so", func() {
			cfg.KibanaEnabled = false
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
			cfg.KeyStoreSecret.Data[render.ElasticsearchKeystoreEnvName] = []byte("12345")
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
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, []resourceTestObj{
				{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
				{render.ESCuratorName, render.ElasticsearchNamespace, &batchv1.CronJob{}, nil},
				{render.ESCuratorName, "", &rbacv1.ClusterRole{}, nil},
				{render.ESCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
				{render.EsCuratorPolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
				{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
				{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
				{render.ESCuratorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
			})

			es := getElasticsearch(createResources)
			Expect(es.Spec.NodeSets[0].PodTemplate.Spec.Containers).To(HaveLen(1))
			esContainer := es.Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
			Expect(esContainer.Env).Should(ContainElement(corev1.EnvVar{
				Name: "ES_JAVA_OPTS",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: render.ElasticsearchKeystoreSecret},
						Key:                  "ES_JAVA_OPTS",
					},
				},
			}))
			initContainers := es.Spec.NodeSets[0].PodTemplate.Spec.InitContainers

			resource := rtest.GetResource(createResources, render.ElasticsearchKeystoreSecret, common.OperatorNamespace(), "", "v1", "Secret")
			Expect(resource).ShouldNot(BeNil())
			keystoreSecret, ok := resource.(*corev1.Secret)
			Expect(ok).To(BeTrue())
			Expect(keystoreSecret.Data["ES_JAVA_OPTS"]).Should(Equal([]byte("-Xms75M -Xmx75M --module-path /usr/share/bc-fips/ -Djavax.net.ssl.trustStore=/usr/share/elasticsearch/config/cacerts.bcfks -Djavax.net.ssl.trustStoreType=BCFKS -Djavax.net.ssl.trustStorePassword=12345 -Dorg.bouncycastle.fips.approved_only=true")))
			Expect(es.Spec.Image).To(ContainSubstring("-fips"))
			Expect(es.Spec.NodeSets[0].PodTemplate.Spec.Containers[0].Env).To(ConsistOf(
				corev1.EnvVar{
					Name: render.ElasticsearchKeystoreEnvName,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: render.ElasticsearchKeystoreSecret},
							Key:                  render.ElasticsearchKeystoreEnvName,
						},
					},
				},
				corev1.EnvVar{
					Name: "ES_JAVA_OPTS",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: render.ElasticsearchKeystoreSecret},
							Key:                  "ES_JAVA_OPTS",
						},
					},
				},
			))
			Expect(initContainers).To(HaveLen(2))
			Expect(initContainers[1].Name).To(Equal("elastic-internal-init-keystore"))
			Expect(initContainers[1].Image).To(ContainSubstring("-fips"))
			Expect(initContainers[1].Command).To(Equal([]string{"/bin/sh"}))
			Expect(initContainers[1].Args).To(Equal([]string{"-c", "/usr/bin/initialize_keystore.sh"}))
			Expect(*initContainers[1].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*initContainers[1].SecurityContext.Privileged).To(BeFalse())
			Expect(*initContainers[1].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
			Expect(*initContainers[1].SecurityContext.RunAsNonRoot).To(BeFalse())
			Expect(*initContainers[1].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
			Expect(initContainers[1].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
					Add:  []corev1.Capability{"CHOWN"},
				},
			))
			Expect(initContainers[1].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))
		})
	})

	Context("Managed cluster", func() {
		var cfg *render.ManagedClusterLogStorageConfiguration
		var managementClusterConnection *operatorv1.ManagementClusterConnection

		BeforeEach(func() {
			replicas := int32(1)
			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			managementClusterConnection = &operatorv1.ManagementClusterConnection{}
			cfg = &render.ManagedClusterLogStorageConfiguration{
				Installation:  installation,
				ClusterDomain: "cluster.local",
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
					{render.LinseedServiceName, render.ElasticsearchNamespace, &corev1.Service{}, func(resource runtime.Object) {
						svc := resource.(*corev1.Service)
						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
						Expect(svc.Spec.ExternalName).Should(Equal(fmt.Sprintf("%s.%s.svc.%s", render.GuardianServiceName, render.GuardianNamespace, dns.DefaultClusterDomain)))
					}},
					{"tigera-linseed-secrets", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-linseed-configmaps", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-linseed", "calico-system", &rbacv1.RoleBinding{}, nil},
					{"tigera-linseed", "tigera-operator", &rbacv1.RoleBinding{}, nil},
				}
				component := render.NewManagedClusterLogStorage(cfg)
				createResources, deleteResources := component.Objects()
				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})
		})

		Context("Deleting LogStorage", deleteLogStorageTests(nil, managementClusterConnection))

		Context("allow-tigera rendering", func() {
			policyNames := []types.NamespacedName{
				{Name: "allow-tigera.elasticsearch-access", Namespace: "tigera-elasticsearch"},
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

					component := render.NewManagedClusterLogStorage(cfg)
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
					{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:           operatorv1.ProviderNone,
				ClusterDomain:      "cluster.local",
				ElasticLicenseType: render.ElasticsearchLicenseTypeEnterpriseTrial,
				UsePSP:             true,
				KibanaEnabled:      true,
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
						"node.master":                     "true",
						"node.data":                       "true",
						"node.ingest":                     "true",
						"cluster.max_shards_per_node":     10000,
						"ingest.geoip.downloader.enabled": false,
						"node.attr.zone":                  "us-west-2a",
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
						"node.master":                     "true",
						"node.data":                       "true",
						"node.ingest":                     "true",
						"cluster.max_shards_per_node":     10000,
						"ingest.geoip.downloader.enabled": false,
						"node.attr.zone":                  "us-west-2b",
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
						"node.master":                     "true",
						"node.data":                       "true",
						"node.ingest":                     "true",
						"cluster.max_shards_per_node":     10000,
						"ingest.geoip.downloader.enabled": false,
						"node.attr.zone":                  "us-west-2a",
						"node.attr.rack":                  "rack1",
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
						"node.master":                     "true",
						"node.data":                       "true",
						"node.ingest":                     "true",
						"cluster.max_shards_per_node":     10000,
						"ingest.geoip.downloader.enabled": false,
						"node.attr.zone":                  "us-west-2b",
						"node.attr.rack":                  "rack1",
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
				KibanaEnabled:        true,
				TrustedBundle:        trustedBundle,
				PullSecrets: []*corev1.Secret{
					{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
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

		It("should render the kibana pod template with resource requests and limits when set", func() {

			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{
				CACert:             cfg.ElasticsearchKeyPair.GetCertificatePEM(),
				SignerName:         "my signer name",
				SignatureAlgorithm: "ECDSAWithSHA256",
				KeyAlgorithm:       "ECDSAWithCurve521",
			}

			cfg.ElasticsearchKeyPair, cfg.KibanaKeyPair, cfg.TrustedBundle = getTLS(cfg.Installation)
			cfg.UnusedTLSSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.UnusedCertSecret, Namespace: common.OperatorNamespace()},
			}
			expectedResourcesRequirements := corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":    resource.MustParse("1"),
					"memory": resource.MustParse("500Mi"),
				},
				Requests: corev1.ResourceList{
					"cpu":    resource.MustParse("101m"),
					"memory": resource.MustParse("100Mi"),
				},
			}

			cfg.LogStorage.Spec.Kibana = &operatorv1.Kibana{
				Spec: &operatorv1.KibanaSpec{
					Template: &operatorv1.KibanaPodTemplateSpec{
						Spec: &operatorv1.KibanaPodSpec{
							Containers: []operatorv1.KibanaContainer{
								{
									Name:      "kibana",
									Resources: &expectedResourcesRequirements},
							},
							InitContainers: []operatorv1.KibanaInitContainer{
								{
									Name:      "key-cert-provisioner",
									Resources: &expectedResourcesRequirements,
								},
							},
						},
					},
				},
			}

			component := render.LogStorage(cfg)
			resources, _ := component.Objects()

			kibana, ok := rtest.GetResource(resources, "tigera-secure", "tigera-kibana", "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
			Expect(ok).To(BeTrue())
			Expect(kibana.Spec.Count).To(Equal(int32(1)))
			container := test.GetContainer(kibana.Spec.PodTemplate.Spec.Containers, "kibana")
			Expect(container).NotTo(BeNil())
			Expect(container.Resources).To(Equal(expectedResourcesRequirements))

			initcontainer := test.GetContainer(kibana.Spec.PodTemplate.Spec.InitContainers, "key-cert-provisioner")
			Expect(initcontainer).NotTo(BeNil())
			Expect(initcontainer.Resources).To(Equal(expectedResourcesRequirements))

		})
	})
})

func getTLS(installation *operatorv1.InstallationSpec) (certificatemanagement.KeyPairInterface, certificatemanagement.KeyPairInterface, certificatemanagement.TrustedBundle) {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
	cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
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
				LogStorage:           logStorage,
				Installation:         installation,
				ManagementCluster:    managementCluster,
				Elasticsearch:        &esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
				Kibana:               &kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace}},
				KibanaEnabled:        true,
				ClusterConfig:        esConfig,
				ElasticsearchKeyPair: elasticsearchKeyPair,
				KibanaKeyPair:        kibanaKeyPair,
				TrustedBundle:        trustedBundle,
				PullSecrets: []*corev1.Secret{
					{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
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
	ExpectWithOffset(1, len(resources)).To(Equal(len(expectedResources)))
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
