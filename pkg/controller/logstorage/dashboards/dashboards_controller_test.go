// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package dashboards

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/render/logstorage/dashboards"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/test"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var successResult = reconcile.Result{}

func NewDashboardsControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
	multiTenant bool,
	externalElastic bool,
) (*DashboardsSubController, error) {
	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		MultiTenant:      multiTenant,
		ElasticExternal:  externalElastic,
	}

	r := &DashboardsSubController{
		client:          cli,
		scheme:          scheme,
		status:          status,
		clusterDomain:   opts.ClusterDomain,
		multiTenant:     opts.MultiTenant,
		elasticExternal: opts.ElasticExternal,
		tierWatchReady:  &utils.ReadyFlag{},
	}
	r.tierWatchReady.MarkAsReady()
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage Dashboards controller", func() {
	var (
		cli        client.Client
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
		mockStatus *status.MockStatus
		r          *DashboardsSubController
	)

	BeforeEach(func() {
		// This BeforeEach contains common preparation for all tests - both single-tenant and multi-tenant.
		// Any test-specific preparation should be done in subsequen BeforeEach blocks in the Contexts below.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		ctx = context.Background()
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		// Create a basic Installation.
		var replicas int32 = 2
		install = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Computed: &operatorv1.InstallationSpec{},
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.TigeraSecureEnterprise,
				Registry:             "some.registry.org/",
			},
		}
		Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

		// Create a basic LogStorage.
		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		initializer.FillDefaults(ls)
		Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

		// Create a basic Elasticsearch instance.
		es := &esv1.Elasticsearch{}
		es.Name = "tigera-secure"
		es.Namespace = render.ElasticsearchNamespace
		es.Status.Phase = esv1.ElasticsearchReadyPhase
		Expect(cli.Create(ctx, es)).ShouldNot(HaveOccurred())

		// Create the allow-tigera Tier, since the controller blocks on its existence.
		tier := &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}}
		Expect(cli.Create(ctx, tier)).ShouldNot(HaveOccurred())
	})

	Context("Zero tenant", func() {
		BeforeEach(func() {
			mockStatus = &status.MockStatus{}
			mockStatus.On("Run").Return()
			mockStatus.On("AddDaemonsets", mock.Anything)
			mockStatus.On("AddDeployments", mock.Anything)
			mockStatus.On("AddStatefulSets", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			mockStatus.On("ClearDegraded")

			// Create a CA secret for the test, and create its KeyPair.
			cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

			// Create secrets needed for successful installation.
			bundle := cm.CreateTrustedBundle()
			Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).ShouldNot(HaveOccurred())

			// Create the ES user secret. Generally this is created by either es-kube-controllers or the user controller in this operator.
			userSecret := &corev1.Secret{}
			userSecret.Name = dashboards.ElasticCredentialsSecret
			userSecret.Namespace = render.ElasticsearchNamespace
			userSecret.Data = map[string][]byte{"username": []byte("test-username"), "password": []byte("test-password")}
			Expect(cli.Create(ctx, userSecret)).ShouldNot(HaveOccurred())

			// Create the reconciler for the tests.
			r, err = NewDashboardsControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, false, false)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should wait for the cluster CA to be provisioned", func() {
			// Delete the CA secret for this test.
			caSecret := &corev1.Secret{}
			caSecret.Name = certificatemanagement.CASecretName
			caSecret.Namespace = common.OperatorNamespace()
			Expect(cli.Delete(ctx, caSecret)).ShouldNot(HaveOccurred())

			// Run the reconciler.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("CA secret"))
		})

		It("should reconcile resources for a standalone cluster/management cluster", func() {
			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			// Check that K8s Job was created as expected. We don't need to check every resource in detail, since
			// the render package has its own tests which cover this in more detail.
			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &dashboardJob)).To(BeNil())
		})

		It("should not reconcile resources for a managed cluster", func() {
			managementClusterConnection := &operatorv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
			}
			Expect(cli.Create(ctx, managementClusterConnection)).ShouldNot(HaveOccurred())

			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			// Check that K8s Job was not created
			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &dashboardJob)).To(HaveOccurred())
		})

		It("should use images from ImageSet", func() {
			Expect(cli.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/intrusion-detection-job-installer", Digest: "sha256:dashboardhash"},
						{Image: "tigera/key-cert-provisioner", Digest: "sha256:deadbeef0123456789"},
					},
				},
			})).ToNot(HaveOccurred())

			// Reconcile the resources
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &dashboardJob)).To(BeNil())
			dashboardInstaller := test.GetContainer(dashboardJob.Spec.Template.Spec.Containers, dashboards.Name)
			Expect(dashboardInstaller).ToNot(BeNil())
			Expect(dashboardInstaller.Image).To(Equal(fmt.Sprintf("some.registry.org/%s@%s", components.ComponentElasticTseeInstaller.Image, "sha256:dashboardhash")))
		})
	})

	Context("Multi-tenant", func() {
		var tenantNS string
		var tenant *operatorv1.Tenant

		BeforeEach(func() {
			// Create the tenant Namespace.
			tenantNS = "tenant-namespace"
			Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tenantNS}})).ShouldNot(HaveOccurred())

			// Create the Tenant object.
			tenant = &operatorv1.Tenant{}
			tenant.Name = "default"
			tenant.Namespace = tenantNS
			tenant.Spec.ID = "test-tenant-id"
			tenant.Spec.Indices = []operatorv1.Index{
				{BaseIndexName: "calico_alerts", DataType: operatorv1.DataTypeAlerts},
				{BaseIndexName: "calico_auditlogs", DataType: operatorv1.DataTypeAuditLogs},
				{BaseIndexName: "calico_bgplogs", DataType: operatorv1.DataTypeBGPLogs},
				{BaseIndexName: "calico_compliance_benchmarks", DataType: operatorv1.DataTypeComplianceBenchmarks},
				{BaseIndexName: "calico_compliance_reports", DataType: operatorv1.DataTypeComplianceReports},
				{BaseIndexName: "calico_compliance_snapshots", DataType: operatorv1.DataTypeComplianceSnapshots},
				{BaseIndexName: "calico_dnslogs", DataType: operatorv1.DataTypeDNSLogs},
				{BaseIndexName: "calico_flowlogs", DataType: operatorv1.DataTypeFlowLogs},
				{BaseIndexName: "calico_L7logs", DataType: operatorv1.DataTypeL7Logs},
				{BaseIndexName: "calico_runtime_reports", DataType: operatorv1.DataTypeRuntimeReports},
				{BaseIndexName: "calico_threat_feeds_domain_name_set", DataType: operatorv1.DataTypeThreatFeedsDomainSet},
				{BaseIndexName: "calico_threat_feeds_ip_set", DataType: operatorv1.DataTypeThreatFeedsIPSet},
				{BaseIndexName: "calico_waf", DataType: operatorv1.DataTypeWAFLogs},
			}
			Expect(cli.Create(ctx, tenant)).ShouldNot(HaveOccurred())

			mockStatus = &status.MockStatus{}
			mockStatus.On("Run").Return()
			mockStatus.On("AddDaemonsets", mock.Anything)
			mockStatus.On("AddDeployments", mock.Anything)
			mockStatus.On("AddStatefulSets", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			mockStatus.On("ClearDegraded")

			// Create a CA secret for the test, and create its KeyPair.
			opts := []certificatemanager.Option{
				certificatemanager.AllowCACreation(),
				certificatemanager.WithTenant(tenant),
			}
			cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, tenantNS, opts...)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, cm.KeyPair().Secret(tenantNS))).ShouldNot(HaveOccurred())

			// Create secrets needed for successful installation.
			bundle := cm.CreateTrustedBundle()
			Expect(cli.Create(ctx, bundle.ConfigMap(tenantNS))).ShouldNot(HaveOccurred())

			// Create the ES user secret. Generally this is created by either es-kube-controllers or the user controller in this operator.
			userSecret := &corev1.Secret{}
			userSecret.Name = dashboards.ElasticCredentialsSecret
			userSecret.Namespace = tenantNS
			userSecret.Data = map[string][]byte{"username": []byte("test-username"), "password": []byte("test-password")}
			Expect(cli.Create(ctx, userSecret)).ShouldNot(HaveOccurred())

			// Create the reconciler for the test.
			r, err = NewDashboardsControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, true, false)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should wait for the tenant CA to be provisioned", func() {
			// Delete the CA secret for this test.
			caSecret := &corev1.Secret{}
			caSecret.Name = certificatemanagement.TenantCASecretName
			caSecret.Namespace = tenantNS
			Expect(cli.Delete(ctx, caSecret)).ShouldNot(HaveOccurred())

			// Run the reconciler.
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("CA secret"))
		})

		It("should not reconcile any resources if no Namespace was given", func() {
			// Run the reconciler, passing in a Request with no Namespace. It should return successfully.
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that nothing was installed on the cluster.
			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			err = cli.Get(ctx, types.NamespacedName{Name: dashboardJob.Name, Namespace: dashboardJob.Namespace}, &dashboardJob)
			Expect(err).Should(HaveOccurred())
			Expect(errors.IsNotFound(err)).Should(BeTrue())

			// Check that OnCRFound was not called.
			mockStatus.AssertNotCalled(GinkgoT(), "OnCRFound")
		})

		It("should reconcile resources for a tenant", func() {
			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			// Check that Dashboards was created as expected. We don't need to check every resource in detail, since
			// the render package has its own tests which cover this in more detail.
			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: tenantNS,
				},
			}
			Expect(test.GetResource(cli, &dashboardJob)).To(BeNil())
		})

		It("should use images from ImageSet", func() {
			Expect(cli.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/intrusion-detection-job-installer", Digest: "sha256:dashboardhash"},
						{Image: "tigera/key-cert-provisioner", Digest: "sha256:deadbeef0123456789"},
					},
				},
			})).ToNot(HaveOccurred())

			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: tenantNS,
				},
			}
			Expect(test.GetResource(cli, &dashboardJob)).To(BeNil())
			job := test.GetContainer(dashboardJob.Spec.Template.Spec.Containers, dashboards.Name)
			Expect(job).ToNot(BeNil())
			Expect(job.Image).To(Equal(fmt.Sprintf("some.registry.org/%s@%s", components.ComponentElasticTseeInstaller.Image, "sha256:dashboardhash")))
		})

		Context("External Kibana mode", func() {
			BeforeEach(func() {
				// Delete the Elasticsearch instance, since this is only used for ECK mode.
				es := &esv1.Elasticsearch{}
				es.Name = "tigera-secure"
				es.Namespace = render.ElasticsearchNamespace
				Expect(cli.Delete(ctx, es)).ShouldNot(HaveOccurred())

				// Set the reconcile to run in external ES mode.
				r.elasticExternal = true
				r.multiTenant = true

				// Set the elasticsearch configuration for the tenant.
				tenant.Spec.Elastic = &operatorv1.TenantElasticSpec{KibanaURL: "https://external-kibana:5601"}
				Expect(cli.Update(ctx, tenant)).ShouldNot(HaveOccurred())
			})

			It("should reconcile resources", func() {
				// Run the reconciler.
				result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: tenant.Name, Namespace: tenant.Namespace}})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(successResult))

				// SetDegraded should not have been called.
				mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)

				// Check that Dashboards was created as expected. We don't need to check every resource in detail, since
				// the render package has its own tests which cover this in more detail.
				dashboardJob := batchv1.Job{
					TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      dashboards.Name,
						Namespace: tenantNS,
					},
				}
				Expect(test.GetResource(cli, &dashboardJob)).To(BeNil())

				// Check that the correct External ES environment variables are set.
				dashboards := test.GetContainer(dashboardJob.Spec.Template.Spec.Containers, dashboards.Name)
				Expect(dashboards).ToNot(BeNil())
				Expect(dashboards.Env).To(ContainElement(corev1.EnvVar{Name: "KIBANA_SCHEME", Value: "https"}))
				Expect(dashboards.Env).To(ContainElement(corev1.EnvVar{Name: "KIBANA_HOST", Value: "external-kibana"}))
				Expect(dashboards.Env).To(ContainElement(corev1.EnvVar{Name: "KIBANA_PORT", Value: "5601"}))
			})

			It("should reconcile with mTLS enabled", func() {
				// Update the tenant with mTLS
				tenant.Spec.Elastic.MutualTLS = true
				tenant.Spec.Elastic.KibanaURL = "https://external-kibana:5601"
				Expect(cli.Update(ctx, tenant)).ShouldNot(HaveOccurred())

				// Create a dummy secret mocking the client certificates.
				esClientSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: logstorage.ExternalCertsSecret, Namespace: common.OperatorNamespace()},
					Data:       map[string][]byte{"client.crt": []byte("cert"), "client.key": []byte("key")},
				}
				Expect(cli.Create(ctx, esClientSecret)).ShouldNot(HaveOccurred())

				// Run the reconciler.
				result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: tenant.Name, Namespace: tenant.Namespace}})
				Expect(err).NotTo(HaveOccurred())
				Expect(result).Should(Equal(successResult))

				// SetDegraded should not have been called.
				mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)

				// Check that Dashboards was created as expected. We don't need to check every resource in detail, since
				// the render package has its own tests which cover this in more detail.
				dashboardJob := batchv1.Job{
					TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      dashboards.Name,
						Namespace: tenantNS,
					},
				}
				Expect(test.GetResource(cli, &dashboardJob)).To(BeNil())

				// Expect the correct volume and mounts to be present.
				job := test.GetContainer(dashboardJob.Spec.Template.Spec.Containers, dashboards.Name)
				Expect(job).ToNot(BeNil())
				Expect(job.VolumeMounts).To(ContainElement(corev1.VolumeMount{
					Name:      "tigera-secure-external-es-certs",
					MountPath: "/certs/kibana/mtls",
					ReadOnly:  true,
				}))
			})
		})
	})
})
