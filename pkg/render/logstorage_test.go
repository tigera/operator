// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/esgateway"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
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
	Context("Standalone cluster type", func() {
		var logStorage *operatorv1.LogStorage
		var installation *operatorv1.InstallationSpec
		replicas := int32(1)
		retention := int32(1)

		var esConfig *relasticsearch.ClusterConfig

		BeforeEach(func() {
			logStorage = &operatorv1.LogStorage{
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
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}

			esConfig = relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
		})

		It("should not panic if an empty spec is provided", func() {
			// Override with an instance that has no spec.
			logStorage = &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{},
			}

			component := render.LogStorage(
				logStorage,
				installation, nil, nil, nil, nil,
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

			// Render the objects and make sure we don't panic!
			_, _ = component.Objects()
		})

		Context("Initial creation", func() {
			It("should render an elasticsearchComponent", func() {
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
						ls := resource.(*operatorv1.LogStorage)
						Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
					}},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{relasticsearch.ClusterConfigConfigMapName, rmeta.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-kibana", render.KibanaNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsKubeControllerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
					{render.EsKubeControllerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				}
				component := render.LogStorage(
					logStorage,
					installation, nil, nil, nil, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})

				resultES := rtest.GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)

				// There are no node selectors in the LogStorage CR, so we expect no node selectors in the Elasticsearch CR.
				nodeSet := resultES.Spec.NodeSets[0]
				Expect(nodeSet.PodTemplate.Spec.NodeSelector).To(BeEmpty())

				// Verify that an initContainer is added
				initContainers := resultES.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
				Expect(len(initContainers)).To(Equal(1))
				Expect(initContainers[0].Name).To(Equal("elastic-internal-init-os-settings"))

				// Verify that the default container limits/requests are set.
				esContainer := resultES.Spec.NodeSets[0].PodTemplate.Spec.Containers[0]
				limits := esContainer.Resources.Limits
				resources := esContainer.Resources.Requests

				Expect(limits.Cpu().String()).To(Equal("1"))
				Expect(limits.Memory().String()).To(Equal("4Gi"))
				Expect(resources.Cpu().String()).To(Equal("250m"))
				Expect(resources.Memory().String()).To(Equal("4Gi"))
				Expect(esContainer.Env[0].Value).To(Equal("-Xms1398101K -Xmx1398101K"))

				//Check that the expected config made it's way to the Elastic CR
				Expect(nodeSet.Config.Data).Should(Equal(map[string]interface{}{
					"node.master":                 "true",
					"node.data":                   "true",
					"node.ingest":                 "true",
					"cluster.max_shards_per_node": 10000,
				}))
			})
			It("should render an elasticsearchComponent and delete the Elasticsearch and Kibana ExternalService", func() {
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
						ls := resource.(*operatorv1.LogStorage)
						Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
					}},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{relasticsearch.ClusterConfigConfigMapName, rmeta.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-kibana", render.KibanaNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsKubeControllerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
					{render.EsKubeControllerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				}

				expectedDeleteResources := []resourceTestObj{
					{render.ElasticsearchServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
					{render.KibanaServiceName, render.KibanaNamespace, &corev1.Service{}, nil},
				}

				component := render.LogStorage(
					logStorage,
					installation, nil, nil, nil, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operatorv1.ProviderNone, nil,
					&corev1.Service{
						ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace},
						Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName},
					},
					&corev1.Service{
						ObjectMeta: metav1.ObjectMeta{Name: render.KibanaServiceName, Namespace: render.KibanaNamespace},
						Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName},
					}, "cluster.local", nil, render.ElasticsearchLicenseTypeBasic)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, expectedDeleteResources)
			})

			It("should render an elasticsearchComponent with certificate management enabled", func() {

				installation.CertificateManagement = &operatorv1.CertificateManagement{
					CACert:             []byte("my-cert"),
					SignerName:         "my signer name",
					SignatureAlgorithm: "ECDSAWithSHA256",
					KeyAlgorithm:       "ECDSAWithCurve521",
				}
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
						ls := resource.(*operatorv1.LogStorage)
						Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
					}},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{relasticsearch.ClusterConfigConfigMapName, rmeta.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-kibana", render.KibanaNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsKubeControllerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
					{render.EsKubeControllerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
					// Certificate management comes with two additional cluster role bindings:
					{"tigera-elasticsearch:csr-creator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana:csr-creator", "", &rbacv1.ClusterRoleBinding{}, nil},
				}
				component := render.LogStorage(
					logStorage,
					installation, nil, nil, nil, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})

				resultES := rtest.GetResource(createResources, render.ElasticsearchName, render.ElasticsearchNamespace,
					"elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch)

				initContainers := resultES.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
				Expect(initContainers).To(HaveLen(4))
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
					{Name: "elastic-internal-transport-certificates-secret", MountPath: "/mnt/elastic-internal/transport-certificates"},
					{Name: "elastic-internal-transport-certificates", MountPath: "/csr"},
					{Name: "elastic-internal-elasticsearch-config-local", MountPath: "/mnt/elastic-internal/elasticsearch-config-local"},
					{Name: "elastic-internal-elasticsearch-bin-local", MountPath: "/mnt/elastic-internal/elasticsearch-bin-local"},
				})
				compareInitContainer(initContainers[2], "key-cert-elastic", []corev1.VolumeMount{
					{Name: "elastic-internal-http-certificates", MountPath: render.CSRCMountPath},
				})
				compareInitContainer(initContainers[3], "key-cert-elastic-transport", []corev1.VolumeMount{
					{Name: "elastic-internal-transport-certificates", MountPath: render.CSRCMountPath},
				})
			})

		})

		Context("Elasticsearch and Kibana both ready", func() {
			It("should render correctly", func() {
				expectedCreateResources := []resourceTestObj{
					{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
						ls := resource.(*operatorv1.LogStorage)
						Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
					}},
					{render.ECKOperatorNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ECKOperatorNamespace, &corev1.Secret{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRole{}, nil},
					{"elastic-operator", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"elastic-operator", render.ECKOperatorNamespace, &corev1.ServiceAccount{}, nil},
					{render.ECKOperatorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-elasticsearch", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-elasticsearch", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRoleBinding{}, nil},
					{"tigera-kibana", "", &rbacv1.ClusterRole{}, nil},
					{"tigera-kibana", "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.ECKOperatorName, render.ECKOperatorNamespace, &appsv1.StatefulSet{}, nil},
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-pull-secret", render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraElasticsearchCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{relasticsearch.PublicCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{"tigera-elasticsearch", render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{relasticsearch.ClusterConfigConfigMapName, rmeta.OperatorNamespace(), &corev1.ConfigMap{}, nil},
					{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{"tigera-kibana", render.KibanaNamespace, &corev1.ServiceAccount{}, nil},
					{"tigera-pull-secret", render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.TigeraKibanaCertSecret, render.KibanaNamespace, &corev1.Secret{}, nil},
					{render.KibanaPublicCertSecret, rmeta.OperatorNamespace(), &corev1.Secret{}, nil},
					{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
					{render.ElasticsearchCuratorUserSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, &corev1.Secret{}, nil},
					{render.EsCuratorServiceAccount, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
					{render.EsCuratorName, "", &rbacv1.ClusterRole{}, nil},
					{render.EsCuratorName, "", &rbacv1.ClusterRoleBinding{}, nil},
					{render.EsCuratorName, "", &policyv1beta1.PodSecurityPolicy{}, nil},
					{render.EsCuratorName, render.ElasticsearchNamespace, &batchv1beta.CronJob{}, nil},
					{render.EsManagerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsKubeControllerRole, render.ElasticsearchNamespace, &rbacv1.Role{}, nil},
					{render.EsManagerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
					{render.EsKubeControllerRoleBinding, render.ElasticsearchNamespace, &rbacv1.RoleBinding{}, nil},
				}
				component := render.LogStorage(
					logStorage,
					installation, nil, nil, nil, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: rmeta.OperatorNamespace()}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: rmeta.OperatorNamespace()}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operatorv1.ProviderNone,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: rmeta.OperatorNamespace()}},
					},
					nil, nil, dns.DefaultClusterDomain, nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})
		})

		Context("Deleting LogStorage", deleteLogStorageTests(nil, nil))

		Context("Updating LogStorage resource", func() {
			It("should create new NodeSet", func() {
				ls := &operatorv1.LogStorage{
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

				es := &esv1.Elasticsearch{}

				component := render.LogStorage(
					ls,
					installation, nil, nil, es, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

				createResources, _ := component.Objects()

				oldNodeSetName := rtest.GetResource(createResources, "tigera-secure-internal", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch).Spec.NodeSets[0].Name

				// update resource requirements
				ls.Spec.Nodes.ResourceRequirements = &corev1.ResourceRequirements{
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

				updatedComponent := render.LogStorage(
					ls,
					installation, nil, nil, es, nil,
					esConfig,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
						{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					},
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

				updatedResources, _ := updatedComponent.Objects()

				// Check updates to storage requirements are reflected
				Expect(updatedResources[0].(*operatorv1.LogStorage).Spec.Nodes.ResourceRequirements).
					Should(Equal(ls.Spec.Nodes.ResourceRequirements))

				newNodeName := rtest.GetResource(updatedResources, "tigera-secure-internal", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch").(*esv1.Elasticsearch).Spec.NodeSets[0].Name
				Expect(newNodeName).NotTo(Equal(oldNodeSetName))
			})
		})

		It("should render DataNodeSelectors defined in the LogStorage CR", func() {
			logStorage.Spec.DataNodeSelector = map[string]string{
				"k1": "v1",
				"k2": "v2",
			}
			component := render.LogStorage(
				logStorage,
				installation, nil, nil, nil, nil,
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

			// Verify that the node selectors are passed into the Elasticsearch pod spec.
			createResources, _ := component.Objects()
			nodeSelectors := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.NodeSelector
			Expect(nodeSelectors["k1"]).To(Equal("v1"))
			Expect(nodeSelectors["k2"]).To(Equal("v2"))
		})

		It("Configures OIDC for Kibana when the OIDC configuration is provided", func() {
			dexCfg := render.NewDexRelyingPartyConfig(&operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:       "https://example.com",
						UsernameClaim:   "email",
						GroupsClaim:     "group",
						RequestedScopes: []string{"scope"},
					},
				},
			}, render.CreateDexTLSSecret("cn"), render.CreateDexClientSecret(), "cluster.local")

			component := render.LogStorage(
				logStorage,
				installation, nil, nil, nil, nil,
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", dexCfg, render.ElasticsearchLicenseTypeEnterpriseTrial,
			)

			createResources, _ := component.Objects()
			securitySecret := rtest.GetResource(createResources, render.ElasticsearchSecureSettingsSecretName, render.ElasticsearchNamespace, "", "", "")

			Expect(securitySecret).ShouldNot(BeNil())
			Expect(securitySecret.(*corev1.Secret).Data["xpack.security.authc.realms.oidc.oidc1.rp.client_secret"]).Should(HaveLen(24))
			elasticsearch := getElasticsearch(createResources)
			Expect(elasticsearch.Spec.NodeSets[0].Config.Data).Should(Equal(map[string]interface{}{
				"cluster.max_shards_per_node": 10000,
				"xpack.security.authc.realms.oidc.oidc1": map[string]interface{}{
					"rp.client_id":                "tigera-manager",
					"rp.requested_scopes":         []string{"openid", "email", "profile", "groups", "offline_access"},
					"op.jwkset_path":              "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys",
					"op.userinfo_endpoint":        "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/userinfo",
					"claims.principal":            "email",
					"order":                       1,
					"rp.response_type":            "code",
					"rp.redirect_uri":             "https://example.com/tigera-kibana/api/security/oidc/callback",
					"op.issuer":                   "https://example.com/dex",
					"op.authorization_endpoint":   "https://example.com/dex/auth",
					"op.token_endpoint":           "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/token",
					"rp.post_logout_redirect_uri": "https://example.com/tigera-kibana/logged_out",
					"claims.groups":               "groups",
					"ssl.certificate_authorities": []string{"/usr/share/elasticsearch/config/dex/tls-dex.crt"},
				},
				"node.master": "true",
				"node.data":   "true",
				"node.ingest": "true",
			}))

			// Verify that there are 2 init containers for OIDC
			initContainers := elasticsearch.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
			Expect(len(initContainers)).To(Equal(2))
			Expect(initContainers[0].Name).To(Equal("elastic-internal-init-os-settings"))
			Expect(initContainers[1].Name).To(Equal("elastic-internal-init-keystore"))
		})

		It("should not configures OIDC for Kibana when elasticsearch basic license is used", func() {

			dexCfg := render.NewDexRelyingPartyConfig(&operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:       "https://example.com",
						UsernameClaim:   "email",
						GroupsClaim:     "group",
						RequestedScopes: []string{"scope"},
					},
				},
			}, render.CreateDexTLSSecret("cn"), render.CreateDexClientSecret(), "svc.cluster.local")

			component := render.LogStorage(
				logStorage,
				installation, nil, nil, nil, nil,
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", dexCfg, render.ElasticsearchLicenseTypeBasic)

			createResources, _ := component.Objects()
			securitySecret := rtest.GetResource(createResources, render.ElasticsearchSecureSettingsSecretName, render.ElasticsearchNamespace, "", "", "")
			Expect(securitySecret).Should(BeNil())
			elasticsearch := getElasticsearch(createResources)
			Expect(elasticsearch.Spec.NodeSets[0].Config.Data).Should(Equal(map[string]interface{}{
				"cluster.max_shards_per_node": 10000,
				"node.master":                 "true",
				"node.data":                   "true",
				"node.ingest":                 "true",
			}))

			initContainers := elasticsearch.Spec.NodeSets[0].PodTemplate.Spec.InitContainers
			Expect(len(initContainers)).To(Equal(1))
			Expect(initContainers[0].Name).To(Equal("elastic-internal-init-os-settings"))
		})

		Context("ECKOperator memory requests/limits", func() {
			When("LogStorage Spec contains an entry for ECKOperator in ComponentResources", func() {
				It("should set matching memory requests/limits in the elastic-operator StatefulSet.Spec manager container", func() {
					limits := corev1.ResourceList{}
					requests := corev1.ResourceList{}
					limits[corev1.ResourceMemory] = resource.MustParse("512Mi")
					requests[corev1.ResourceMemory] = resource.MustParse("512Mi")
					logStorage.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
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

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
	})

	Context("Managed cluster", func() {
		var installation *operatorv1.InstallationSpec
		var managementClusterConnection *operatorv1.ManagementClusterConnection

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}
			managementClusterConnection = &operatorv1.ManagementClusterConnection{}
		})
		Context("Initial creation", func() {
			It("creates Managed cluster logstorage components", func() {
				expectedCreateResources := []resourceTestObj{
					{render.ElasticsearchNamespace, "", &corev1.Namespace{}, nil},
					{render.KibanaNamespace, "", &corev1.Namespace{}, nil},
					{esgateway.EsGatewayElasticServiceName, render.ElasticsearchNamespace, &corev1.Service{}, func(resource runtime.Object) {
						svc := resource.(*corev1.Service)

						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
						Expect(svc.Spec.ExternalName).Should(Equal(fmt.Sprintf("%s.%s.svc.%s", render.GuardianServiceName, render.GuardianNamespace, dns.DefaultClusterDomain)))
					}},
					{esgateway.EsGatewayKibanaServiceName, render.KibanaNamespace, &corev1.Service{}, func(resource runtime.Object) {
						svc := resource.(*corev1.Service)

						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
						Expect(svc.Spec.ExternalName).Should(Equal(fmt.Sprintf("%s.%s.svc.%s", render.GuardianServiceName, render.GuardianNamespace, dns.DefaultClusterDomain)))
					}},
				}

				component := render.LogStorage(
					nil, installation, nil, managementClusterConnection, nil, nil, nil, nil, nil,
					[]*corev1.Secret{
						{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
					}, operatorv1.ProviderNone,
					nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

				createResources, deleteResources := component.Objects()

				compareResources(createResources, expectedCreateResources)
				compareResources(deleteResources, []resourceTestObj{})
			})
		})
		Context("Deleting LogStorage", deleteLogStorageTests(nil, managementClusterConnection))
	})

	Context("NodeSet configuration", func() {
		var logStorage *operatorv1.LogStorage
		var installation *operatorv1.InstallationSpec
		var esConfig *relasticsearch.ClusterConfig

		replicas, retention := int32(1), int32(1)

		BeforeEach(func() {
			logStorage = &operatorv1.LogStorage{
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
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}
			esConfig = relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
		})
		Context("Node distribution", func() {
			When("the number of Nodes and NodeSets is 3", func() {
				It("creates 3 1 Node NodeSet", func() {
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 3,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 2,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 6,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count: 5,
						NodeSets: []operatorv1.NodeSet{
							{}, {}, {},
						},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

					createResources, _ := component.Objects()
					podResource := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0].Resources
					Expect(podResource).Should(Equal(res))
				})
				It("sets default memory and cpu requirements in pod template", func() {
					res := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"memory": resource.MustParse("10Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu": resource.MustParse("250m"),
						},
					}
					expectedRes := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse(defaultLimitCpu),
							"memory": resource.MustParse("10Gi"),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("250m"),
							"memory": resource.MustParse(defaultRequestsMemory),
						},
					}
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

					createResources, _ := component.Objects()
					podResource := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0].Resources
					Expect(podResource).Should(Equal(expectedRes))
				})
				It("sets value of Limits to user's Requests when user's Limits is not set and default Limits is lesser than Requests", func() {
					res := corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse("2Gi"),
						},
					}
					expectedRes := corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse(defaultLimitMemory),
						},
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("3"),
							"memory": resource.MustParse("2Gi"),
						},
					}
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

					createResources, _ := component.Objects()
					podResource := getElasticsearch(createResources).Spec.NodeSets[0].PodTemplate.Spec.Containers[0].Resources
					Expect(podResource).Should(Equal(expectedRes))
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
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: &res,
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

					createResources, _ := component.Objects()
					pvcResource := getElasticsearch(createResources).Spec.NodeSets[0].VolumeClaimTemplates[0].Spec.Resources
					Expect(pvcResource).Should(Equal(expected))
				})
			})
		})
		Context("Node selection", func() {
			When("NodeSets is set but empty", func() {
				It("returns the defualt NodeSet", func() {
					logStorage.Spec.Nodes = &operatorv1.Nodes{
						Count:    2,
						NodeSets: []operatorv1.NodeSet{},
					}

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

					createResources, _ := component.Objects()
					nodeSets := getElasticsearch(createResources).Spec.NodeSets

					Expect(len(nodeSets)).Should(Equal(1))
				})
			})
			When("there is a single selection attribute for a NodeSet", func() {
				It("sets the Node Affinity Elasticsearch cluster awareness attributes with the single selection attribute", func() {
					logStorage.Spec.Nodes = &operatorv1.Nodes{
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

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
					logStorage.Spec.Nodes = &operatorv1.Nodes{
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

					component := render.LogStorage(
						logStorage,
						installation, nil, nil, nil, nil,
						esConfig,
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
							{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
						},
						[]*corev1.Secret{
							{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						}, operatorv1.ProviderNone, nil, nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
									MatchExpressions: []corev1.NodeSelectorRequirement{{
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
								}},
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
})

var deleteLogStorageTests = func(managementCluster *operatorv1.ManagementCluster, managementClusterConnection *operatorv1.ManagementClusterConnection) func() {
	return func() {
		var logStorage *operatorv1.LogStorage
		var installation *operatorv1.InstallationSpec
		replicas := int32(1)
		retention := int32(1)
		var esConfig *relasticsearch.ClusterConfig
		BeforeEach(func() {
			t := metav1.Now()

			logStorage = &operatorv1.LogStorage{
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
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation = &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}
			esConfig = relasticsearch.NewClusterConfig("cluster", 1, 1, 1)
		})
		It("returns Elasticsearch and Kibana CR's to delete and keeps the finalizers on the LogStorage CR", func() {
			expectedCreateResources := []resourceTestObj{
				{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
					ls := resource.(*operatorv1.LogStorage)
					Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
				}},
			}

			expectedDeleteResources := []resourceTestObj{
				{render.ElasticsearchName, render.ElasticsearchNamespace, &esv1.Elasticsearch{}, nil},
				{render.KibanaName, render.KibanaNamespace, &kbv1.Kibana{}, nil},
			}

			component := render.LogStorage(
				logStorage,
				installation,
				managementCluster,
				managementClusterConnection,
				&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
				&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace}},
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operatorv1.ProviderNone,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: rmeta.OperatorNamespace()}},
				},
				nil, nil, "cluster.local", nil,
				render.ElasticsearchLicenseTypeEnterpriseTrial)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, expectedDeleteResources)
		})
		It("doesn't return anything to delete when Elasticsearch and Kibana have their deletion times stamps set and the LogStorage finalizers are still set", func() {
			expectedCreateResources := []resourceTestObj{
				{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
					ls := resource.(*operatorv1.LogStorage)
					Expect(ls.Finalizers).Should(ContainElement(render.LogStorageFinalizer))
				}},
			}

			t := metav1.Now()
			component := render.LogStorage(
				logStorage,
				installation,
				managementCluster,
				managementClusterConnection,
				&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace, DeletionTimestamp: &t}},
				&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace, DeletionTimestamp: &t}},
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operatorv1.ProviderNone,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: rmeta.OperatorNamespace()}},
				},
				nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

			createResources, deleteResources := component.Objects()

			compareResources(createResources, expectedCreateResources)
			compareResources(deleteResources, []resourceTestObj{})
		})
		It("removes the finalizers from LogStorage if Elasticsearch and Kibana are both nil", func() {
			expectedCreateResources := []resourceTestObj{
				{"tigera-secure", "", &operatorv1.LogStorage{}, func(resource runtime.Object) {
					ls := resource.(*operatorv1.LogStorage)
					Expect(ls.Finalizers).ShouldNot(ContainElement(render.LogStorageFinalizer))
				}},
			}

			component := render.LogStorage(
				logStorage,
				installation,
				managementCluster,
				managementClusterConnection,
				nil, nil,
				esConfig,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: render.ElasticsearchNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
					{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}},
				},
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				}, operatorv1.ProviderNone,
				[]*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: rmeta.OperatorNamespace()}},
					{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: rmeta.OperatorNamespace()}},
				},
				nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeEnterpriseTrial)

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
	resource := rtest.GetResource(resources, "tigera-secure-internal", "tigera-elasticsearch", "elasticsearch.k8s.elastic.co", "v1", "Elasticsearch")
	Expect(resource).ShouldNot(BeNil())

	return resource.(*esv1.Elasticsearch)
}
