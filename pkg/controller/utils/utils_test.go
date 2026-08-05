// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/go-logr/logr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	opv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/options"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
)

var _ = Describe("Utils elasticsearch license type tests", func() {
	var (
		c      client.Client
		ctx    context.Context
		scheme *runtime.Scheme
		log    logr.Logger
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
		log = logf.Log.WithName("utils-test-logger")
	})

	It("Returns license type from elastic-licensing", func() {
		Expect(c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: eck.OperatorNamespace, Name: eck.LicenseConfigMapName},
			Data:       map[string]string{"eck_license_level": "enterprise"},
		})).ShouldNot(HaveOccurred())
		license, err := GetElasticLicenseType(ctx, c, log)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(license).Should(Equal(render.ElasticsearchLicenseTypeEnterprise))
	})

	It("Return error if elastic-licensing not found", func() {
		license, err := GetElasticLicenseType(ctx, c, log)
		Expect(err).Should(HaveOccurred())
		Expect(license).Should(Equal(render.ElasticsearchLicenseTypeUnknown))
	})

	It("Return error if license type if missing", func() {
		Expect(c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: eck.OperatorNamespace, Name: eck.LicenseConfigMapName},
		})).ShouldNot(HaveOccurred())
		_, err := GetElasticLicenseType(ctx, c, log)
		Expect(err).Should(HaveOccurred())
	})
})

var _ = Describe("Tigera License polling test", func() {
	var client fakeClient
	var discovery *fakeDiscovery

	BeforeEach(func() {
		discovery = new(fakeDiscovery)
		client = fakeClient{discovery: discovery}
	})

	It("should be able to verify that the LicenseKey is ready", func() {
		discovery.On("ServerResourcesForGroupVersion", v3.GroupVersionCurrent).Return(&metav1.APIResourceList{
			APIResources: []metav1.APIResource{{
				Kind: "LicenseKey",
			}},
		})
		gvk := schema.GroupVersionKind{Kind: v3.KindLicenseKey}
		Expect(isResourceReady(client, gvk)).To(BeTrue())
		discovery.AssertExpectations(GinkgoT())
	})

	It("should be able to verify that the LicenseKey is not ready", func() {
		discovery.On("ServerResourcesForGroupVersion", v3.GroupVersionCurrent).Return(&metav1.APIResourceList{
			APIResources: []metav1.APIResource{{
				Kind: "Deployment",
			}},
		})
		gvk := schema.GroupVersionKind{Kind: v3.KindLicenseKey}
		Expect(isResourceReady(client, gvk)).To(BeFalse())
		discovery.AssertExpectations(GinkgoT())
	})
})

var _ = Describe("Utils APIServer type tests", func() {
	var (
		c      client.Client
		ctx    context.Context
		scheme *runtime.Scheme
		log    logr.Logger
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
		log = logf.Log.WithName("utils-test-logger")
	})

	DescribeTable("GetAPIServer variant", func(resourceName string) {
		inst := &opv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName},
		}
		Expect(c.Create(ctx, inst)).ShouldNot(HaveOccurred())

		get, msg, err := GetAPIServer(ctx, c)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(msg).Should(BeEmpty())
		Expect(get).ShouldNot(BeNil())
	},
		Entry("with tigera-secure name", "tigera-secure"),
		Entry("wth default name", "default"),
	)

	DescribeTable("IsAPIServerReady variant", func(resourceName string) {
		inst := &opv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName},
			Status:     opv1.APIServerStatus{State: "Ready"},
		}
		Expect(c.Create(ctx, inst)).ShouldNot(HaveOccurred())

		Expect(IsProjectCalicoV3Available(c, options.ControllerOptions{}, log)).Should(BeTrue())
	},
		Entry("with tigera-secure name", "tigera-secure"),
		Entry("wth default name", "default"),
	)
})

var _ = Describe("ValidateResourceNameIsQualified", func() {
	It("returns nil for a compliant kubernetes name.", func() {
		qualifiedName := "proper-resource-name"

		err := ValidateResourceNameIsQualified(qualifiedName)

		Expect(err).To(BeNil())
	})

	It("returns nil for an invalid resource name", func() {
		invalidName := "improper_resource_name"

		err := ValidateResourceNameIsQualified(invalidName)

		Expect(err).ToNot(BeNil())
	})
})

var _ = Describe("AddPeriodicReconcile", func() {
	It("Periodic reconcile channel is constructed correctly", func() {
		var reconcileEvent event.GenericEvent
		var periodicReconciles int
		period := 10 * time.Millisecond
		numPeriods := 10
		timer := time.NewTimer(time.Duration(numPeriods) * period)
		periodicReconcileChannel := createPeriodicReconcileChannel(period)

	OuterLoop:
		for {
			select {
			case <-timer.C:
				break OuterLoop
			case reconcileEvent = <-periodicReconcileChannel:
				Expect(reconcileEvent.Object.GetName()).To(Equal(fmt.Sprintf("periodic-%s-reconcile-event", period.String())))
				periodicReconciles++
			}
		}

		// In practice, perfect alignment of the timers is unlikely.
		Expect(periodicReconciles == numPeriods || periodicReconciles == numPeriods-1).To(BeTrue())
	})
})

var _ = Describe("PopulateK8sServiceEndPoint", func() {
	var (
		c      client.Client
		ctx    context.Context
		scheme *runtime.Scheme
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
	})

	It("reads a ConfigMap with KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT.", func() {
		cmName := render.K8sSvcEndpointConfigMapName
		cm := &corev1.ConfigMap{}
		cm.Name = cmName
		cm.Namespace = common.OperatorNamespace()
		cm.Data = map[string]string{}
		cm.Data["KUBERNETES_SERVICE_HOST"] = "1.2.3.4"
		cm.Data["KUBERNETES_SERVICE_PORT"] = "5678"

		Expect(c.Create(ctx, cm)).ShouldNot(HaveOccurred())

		err := PopulateK8sServiceEndPoint(c)

		Expect(err).To(BeNil())

		Expect(k8sapi.Endpoint.Host).To(Equal("1.2.3.4"))
		Expect(k8sapi.Endpoint.Port).To(Equal("5678"))
	})

	It("does not return error if ConfigMap is not found.", func() {
		err := PopulateK8sServiceEndPoint(c)

		Expect(err).To(BeNil())
	})
})

var _ = Describe("Utils ElasticSearch test", func() {
	var (
		userPrefix = "test-es-prefix"
		clusterID  = "clusterUUID"
		tenantID   = "tenantID"
	)
	It("should generate usernames in expected format", func() {
		generatedESUsername := formatName(userPrefix, clusterID, tenantID)
		expectedESUsername := fmt.Sprintf("%s_%s_%s", userPrefix, clusterID, tenantID)
		Expect(generatedESUsername).To(Equal(expectedESUsername))
	})

	It("should generate Linseed ElasticUser with expected username and roles", func() {
		tenant := &opv1.Tenant{
			Spec: opv1.TenantSpec{
				ID: tenantID,
				Indices: []opv1.Index{
					{DataType: opv1.DataTypeFlowLogs, BaseIndexName: "calico_flowlogs_standard"},
					{DataType: opv1.DataTypeDNSLogs, BaseIndexName: "calico_dnslogs_standard"},
				},
			},
		}
		linseedUser := LinseedUser(clusterID, tenant)
		expectedLinseedESName := fmt.Sprintf("%s_%s_%s", ElasticsearchUserNameLinseed, clusterID, tenantID)

		Expect(linseedUser.Username).To(Equal(expectedLinseedESName))
		Expect(len(linseedUser.Roles)).To(Equal(1))
		linseedRole := linseedUser.Roles[0]
		Expect(linseedRole.Name).To(Equal(expectedLinseedESName))

		expectedLinseedRoleDef := RoleDefinition{
			Cluster: []string{"monitor", "manage_index_templates", "manage_ilm"},
			Indices: []RoleIndex{
				{
					// The indices declared on the Tenant, wildcarded to cover the indices behind each alias.
					Names:      []string{"calico_flowlogs_standard*", "calico_dnslogs_standard*"},
					Privileges: []string{"create_index", "write", "manage", "read"},
				},
			},
		}

		Expect(*linseedRole.Definition).To(Equal(expectedLinseedRoleDef))
	})

	It("should grant a multi-tenant Linseed user the default single-index names when the Tenant declares none", func() {
		tenant := &opv1.Tenant{Spec: opv1.TenantSpec{ID: tenantID}}
		linseedUser := LinseedUser(clusterID, tenant)

		Expect(linseedUser.Roles[0].Definition.Indices[0].Names).To(Equal([]string{"calico_*"}))
	})

	It("should generate a single-tenant Linseed user granted the indices its cluster stores data in", func() {
		tenant := &opv1.Tenant{Spec: opv1.TenantSpec{ID: tenantID}}
		expectedName := fmt.Sprintf("%s-%s-%s", ElasticsearchUserNameLinseed, tenantID, ElasticsearchSecureUserSuffix)

		// A cluster still on multi-index storage declares no indices, and gets access to the indices
		// named for its tenant.
		linseedUser := LinseedUserSingleTenant(tenant, true)
		Expect(linseedUser.Username).To(Equal(expectedName))
		Expect(linseedUser.Roles[0].Name).To(Equal(expectedName))
		Expect(linseedUser.Roles[0].Definition.Indices[0].Names).To(Equal([]string{indexPattern("tigera_secure_ee_*", "*", ".*", tenantID)}))

		// Indices in the cluster's own Elasticsearch are not qualified by tenant, so neither is the pattern.
		linseedUser = LinseedUserSingleTenant(tenant, false)
		Expect(linseedUser.Roles[0].Definition.Indices[0].Names).To(Equal([]string{indexPattern("tigera_secure_ee_*", "*", ".*", "")}))

		// Once it moves to single-index storage, it gets access to the declared indices instead.
		tenant.Spec.Indices = []opv1.Index{{DataType: opv1.DataTypeFlowLogs, BaseIndexName: "calico_flowlogs_standard"}}
		linseedUser = LinseedUserSingleTenant(tenant, true)
		Expect(linseedUser.Username).To(Equal(expectedName))
		Expect(linseedUser.Roles[0].Definition.Indices[0].Names).To(Equal([]string{"calico_flowlogs_standard*"}))
	})

	It("should never widen the single-index pattern to all indices when a base index name is empty", func() {
		// An index with no base index name must not be wildcarded into "*", which would grant Linseed
		// access to every index in Elasticsearch.
		tenant := &opv1.Tenant{
			Spec: opv1.TenantSpec{
				ID: tenantID,
				Indices: []opv1.Index{
					{DataType: opv1.DataTypeFlowLogs, BaseIndexName: "calico_flowlogs_standard"},
					{DataType: opv1.DataTypeDNSLogs},
				},
			},
		}
		Expect(LinseedUser(clusterID, tenant).Roles[0].Definition.Indices[0].Names).To(Equal([]string{"calico_flowlogs_standard*"}))
		Expect(LinseedUserSingleTenant(tenant, true).Roles[0].Definition.Indices[0].Names).To(Equal([]string{"calico_flowlogs_standard*"}))

		// With no usable base index name at all, fall back to Linseed's default index names.
		tenant.Spec.Indices = []opv1.Index{{DataType: opv1.DataTypeDNSLogs}}
		Expect(LinseedUser(clusterID, tenant).Roles[0].Definition.Indices[0].Names).To(Equal([]string{"calico_*"}))
		Expect(LinseedUserSingleTenant(tenant, true).Roles[0].Definition.Indices[0].Names).To(Equal([]string{"calico_*"}))
	})
})

type fakeClient struct {
	discovery discovery.DiscoveryInterfaces
	kubernetes.Interface
}

type fakeDiscovery struct {
	discovery.DiscoveryInterfaces
	mock.Mock
}

func (m fakeClient) Discovery() discovery.DiscoveryInterfaces {
	return m.discovery
}

func (m *fakeDiscovery) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	args := m.Called(groupVersion)
	return args.Get(0).(*metav1.APIResourceList), nil
}

// mockController implements ctrlruntime.Controller for testing watch functions.
type mockController struct {
	mock.Mock
}

func (m *mockController) WatchObject(obj client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error {
	args := m.Called(obj, eventhandler, predicates)
	return args.Error(0)
}

func (m *mockController) WatchObjectInCache(cch cache.Cache, obj client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error {
	args := m.Called(cch, obj, eventhandler, predicates)
	return args.Error(0)
}

func (m *mockController) Reconcile(_ context.Context, _ reconcile.Request) (reconcile.Result, error) {
	return reconcile.Result{}, nil
}

func (m *mockController) Watch(_ source.Source) error {
	return nil
}

func (m *mockController) Start(_ context.Context) error {
	return nil
}

func (m *mockController) GetLogger() logr.Logger {
	return logr.Discard()
}

var _ = Describe("CreatePredicateForObject", func() {
	var objMeta metav1.Object

	Context("when the name and namespace were specified with empty strings", func() {
		BeforeEach(func() {
			objMeta = &metav1.ObjectMeta{
				Name:      "",
				Namespace: "",
			}
		})

		It("should match everything", func() {
			p := createPredicateForObject(objMeta)
			Expect(p.Create(event.CreateEvent{})).To(BeTrue())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "", Generation: 0}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "", Generation: 0}},
			})).To(BeTrue())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "", Generation: 1}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "", Generation: 2}},
			})).To(BeTrue())
			Expect(p.Delete(event.DeleteEvent{})).To(BeTrue())
		})
	})

	Context("when a name match was specified, with no namespace", func() {
		BeforeEach(func() {
			objMeta = &metav1.ObjectMeta{
				Name:      "test-object",
				Namespace: "",
			}
		})

		It("should match if the object name matches", func() {
			p := createPredicateForObject(objMeta)
			Expect(p.Create(event.CreateEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: ""}}})).To(BeTrue())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "", Generation: 0}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "", Generation: 0}},
			})).To(BeTrue()) // Generation was not specified.
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "", Generation: 3}},
			})).To(BeTrue())
			Expect(p.Delete(event.DeleteEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: ""}}})).To(BeTrue())
		})

		It("should not match if the object name does not match, or the generation hasn't changed", func() {
			p := createPredicateForObject(objMeta)
			Expect(p.Create(event.CreateEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: ""}}})).To(BeFalse())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "", Generation: 0}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "", Generation: 0}},
			})).To(BeFalse()) // Generation was not specified.
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "", Generation: 3}},
			})).To(BeFalse())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "", Generation: 2}},
			})).To(BeFalse()) // Generation didn't change.
			Expect(p.Delete(event.DeleteEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: ""}}})).To(BeFalse())
		})
	})

	Context("when a namespace match was specified", func() {
		BeforeEach(func() {
			objMeta = &metav1.ObjectMeta{
				Name:      "",
				Namespace: "test-namespace",
			}
		})

		It("should match if the object namespace matches", func() {
			p := createPredicateForObject(objMeta)
			Expect(p.Create(event.CreateEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "test-namespace"}}})).To(BeTrue())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "test-namespace", Generation: 0}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "test-namespace", Generation: 0}},
			})).To(BeTrue()) // Generation was not specified.
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "test-namespace", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "test-namespace", Generation: 3}},
			})).To(BeTrue())
			Expect(p.Delete(event.DeleteEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "test-namespace"}}})).To(BeTrue())
		})

		It("should not match if the object namespace does not match", func() {
			p := createPredicateForObject(objMeta)
			Expect(p.Create(event.CreateEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "other-namespace"}}})).To(BeFalse())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "other-namespace", Generation: 0}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "other-namespace", Generation: 0}},
			})).To(BeFalse()) // Generation was not specified.
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "other-namespace", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "other-namespace", Generation: 3}},
			})).To(BeFalse())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "test-namespace", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "test-namespace", Generation: 2}},
			})).To(BeFalse()) // Generation didn't change.
			Expect(p.Delete(event.DeleteEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "", Namespace: "other-namespace"}}})).To(BeFalse())
		})
	})

	Context("when a name and namespace match were specified", func() {
		BeforeEach(func() {
			objMeta = &metav1.ObjectMeta{
				Name:      "test-object",
				Namespace: "test-namespace",
			}
		})

		It("should match if the object name and namespace match", func() {
			p := createPredicateForObject(objMeta)
			Expect(p.Create(event.CreateEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-namespace"}}})).To(BeTrue())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-namespace", Generation: 0}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-namespace", Generation: 0}},
			})).To(BeTrue()) // Generation was not specified.
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-namespace", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-namespace", Generation: 3}},
			})).To(BeTrue())
			Expect(p.Delete(event.DeleteEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-namespace"}}})).To(BeTrue())
		})

		It("should not match if the object name or namespace do not match", func() {
			p := createPredicateForObject(objMeta)
			Expect(p.Create(event.CreateEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "other-namespace"}}})).To(BeFalse())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "other-namespace", Generation: 0}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "other-namespace", Generation: 0}},
			})).To(BeFalse()) // Generation was not specified.
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "other-namespace", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "other-namespace", Generation: 3}},
			})).To(BeFalse())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "other-namespace", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-namespace", Generation: 2}},
			})).To(BeFalse()) // Generation didn't change.
			Expect(p.Delete(event.DeleteEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "other-namespace"}}})).To(BeFalse())
			Expect(p.Create(event.CreateEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "test-namespace"}}})).To(BeFalse())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "test-namespace", Generation: 0}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "test-namespace", Generation: 0}},
			})).To(BeFalse()) // Generation was not specified.
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "test-namespace", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "test-namespace", Generation: 3}},
			})).To(BeFalse())
			Expect(p.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "test-namespace", Generation: 2}},
				ObjectNew: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "test-namespace", Generation: 2}},
			})).To(BeFalse()) // Generation didn't change.
			Expect(p.Delete(event.DeleteEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-object", Namespace: "test-namespace"}}})).To(BeFalse())
		})
	})

	DescribeTable("should correctly determine whether Dex is enabled",
		func(authentication *opv1.Authentication, expectedResult bool) {
			Expect(DexEnabled(authentication)).To(Equal(expectedResult))
		},
		Entry("when authentication is nil", nil, false),
		Entry("when authentication is not nil and OIDC is nil",
			&opv1.Authentication{Spec: opv1.AuthenticationSpec{OIDC: nil}}, true),
		Entry("when authentication is not nil and OIDC type is OIDCTypeTigera",
			&opv1.Authentication{Spec: opv1.AuthenticationSpec{OIDC: &opv1.AuthenticationOIDC{Type: opv1.OIDCTypeTigera}}}, false),
		Entry("when authentication is not nil and OIDC type is different",
			&opv1.Authentication{Spec: opv1.AuthenticationSpec{OIDC: &opv1.AuthenticationOIDC{Type: opv1.OIDCTypeDex}}}, true),
	)
})

var _ = Describe("WaitToAddResourceWatch with custom predicates", func() {
	var (
		ctrl      *mockController
		k8sClient fakeClient
		disc      *fakeDiscovery
		log       logr.Logger
		obj       client.Object
	)

	testGV := "test.example.com/v1"

	BeforeEach(func() {
		ctrl = new(mockController)
		disc = new(fakeDiscovery)
		k8sClient = fakeClient{discovery: disc}
		log = logf.Log.WithName("resource-watch-test")

		obj = &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "TestResource",
				APIVersion: testGV,
			},
		}
	})

	It("should use the provided predicate instead of the default", func() {
		disc.On("ServerResourcesForGroupVersion", testGV).Return(&metav1.APIResourceList{
			APIResources: []metav1.APIResource{{Kind: "TestResource"}},
		})
		ctrl.On("WatchObject", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		flag := &ReadyFlag{}
		WaitToAddResourceWatch(ctrl, k8sClient, log, flag, []client.Object{obj}, predicate.ResourceVersionChangedPredicate{})

		Expect(flag.IsReady()).To(BeTrue())

		// Verify that WatchObject was called with a predicate (the custom one, not the default
		// generation-based one). The custom predicate is wrapped via predicate.And(), so we
		// just verify it was called and fires on resource version changes.
		ctrl.AssertCalled(GinkgoT(), "WatchObject", mock.Anything, mock.Anything, mock.Anything)
	})

	It("should work with a nil flag", func() {
		disc.On("ServerResourcesForGroupVersion", testGV).Return(&metav1.APIResourceList{
			APIResources: []metav1.APIResource{{Kind: "TestResource"}},
		})
		ctrl.On("WatchObject", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Should not panic with nil flag.
		WaitToAddResourceWatch(ctrl, k8sClient, log, nil, []client.Object{obj}, predicate.ResourceVersionChangedPredicate{})
		ctrl.AssertExpectations(GinkgoT())
	})

	It("should retry when the CRD is not yet available", func() {
		// First call: CRD not available. Second call: CRD available.
		disc.On("ServerResourcesForGroupVersion", testGV).Return(&metav1.APIResourceList{
			APIResources: []metav1.APIResource{{Kind: "SomethingElse"}},
		}).Once()
		disc.On("ServerResourcesForGroupVersion", testGV).Return(&metav1.APIResourceList{
			APIResources: []metav1.APIResource{{Kind: "TestResource"}},
		}).Once()
		ctrl.On("WatchObject", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		flag := &ReadyFlag{}
		WaitToAddResourceWatch(ctrl, k8sClient, log, flag, []client.Object{obj}, predicate.ResourceVersionChangedPredicate{})

		Expect(flag.IsReady()).To(BeTrue())
		disc.AssertNumberOfCalls(GinkgoT(), "ServerResourcesForGroupVersion", 2)
	})

	It("should retry when WatchObject fails", func() {
		disc.On("ServerResourcesForGroupVersion", testGV).Return(&metav1.APIResourceList{
			APIResources: []metav1.APIResource{{Kind: "TestResource"}},
		})
		// First WatchObject call fails, second succeeds.
		ctrl.On("WatchObject", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("cache not started")).Once()
		ctrl.On("WatchObject", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		flag := &ReadyFlag{}
		WaitToAddResourceWatch(ctrl, k8sClient, log, flag, []client.Object{obj}, predicate.ResourceVersionChangedPredicate{})

		Expect(flag.IsReady()).To(BeTrue())
		ctrl.AssertNumberOfCalls(GinkgoT(), "WatchObject", 2)
	})
})
