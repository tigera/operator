// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

package initializer

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
)

func NewTestConditionController(
	cli client.Client,
	scheme *runtime.Scheme,
	clusterDomain string,
) (*LogStorageConditions, error) {
	opts := options.AddOptions{
		ClusterDomain:   clusterDomain,
		ShutdownContext: context.TODO(),
	}

	r := &LogStorageConditions{
		client:      cli,
		scheme:      scheme,
		multiTenant: opts.MultiTenant,
	}
	return r, nil
}

var _ = Describe("LogStorage Conditions controller", func() {
	var (
		cli       client.Client
		readyFlag *utils.ReadyFlag
		scheme    *runtime.Scheme
		ctx       context.Context
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()
	})

	generation := int64(2)

	It("should reconcile with one item in tigerastatus conditions", func() {
		ts := &operatorv1.TigeraStatus{
			ObjectMeta: metav1.ObjectMeta{Name: "log-storage"},
			Spec:       operatorv1.TigeraStatusSpec{},
			Status: operatorv1.TigeraStatusStatus{
				Conditions: []operatorv1.TigeraStatusCondition{
					{
						Type:               operatorv1.ComponentAvailable,
						Status:             operatorv1.ConditionTrue,
						Reason:             string(operatorv1.AllObjectsAvailable),
						Message:            "All Objects are available",
						ObservedGeneration: generation,
					},
				},
			},
		}
		Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "tigera-secure",
				Generation: 3,
			},
			Spec: operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{
					Count: int64(1),
				},
			},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewTestConditionController(cli, scheme, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())

		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		// Expect to be waiting for Elasticsearch and Kibana to be functional
		Expect(result).Should(Equal(reconcile.Result{}))

		By("asserting the finalizers have been set on the LogStorage CR")
		instance := &operatorv1.LogStorage{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(1))

		Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
		Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
		Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
		Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
	})

	It("should reconcile with empty tigerastatus conditions", func() {
		ts := &operatorv1.TigeraStatus{
			ObjectMeta: metav1.ObjectMeta{Name: "log-storage"},
			Spec:       operatorv1.TigeraStatusSpec{},
			Status:     operatorv1.TigeraStatusStatus{},
		}
		Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "tigera-secure",
				Generation: 3,
			},
			Spec: operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{
					Count: int64(1),
				},
			},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewTestConditionController(cli, scheme, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		// Expect to be waiting for Elasticsearch and Kibana to be functional
		Expect(result).Should(Equal(reconcile.Result{}))

		By("asserting the finalizers have been set on the LogStorage CR")
		instance := &operatorv1.LogStorage{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(0))
	})

	It("should reconcile with creating new status condition with multiple conditions as true", func() {
		ts := &operatorv1.TigeraStatus{
			ObjectMeta: metav1.ObjectMeta{Name: "log-storage"},
			Spec:       operatorv1.TigeraStatusSpec{},
			Status: operatorv1.TigeraStatusStatus{
				Conditions: []operatorv1.TigeraStatusCondition{
					{
						Type:               operatorv1.ComponentAvailable,
						Status:             operatorv1.ConditionTrue,
						Reason:             string(operatorv1.AllObjectsAvailable),
						Message:            "All Objects are available",
						ObservedGeneration: generation,
					},
					{
						Type:               operatorv1.ComponentProgressing,
						Status:             operatorv1.ConditionTrue,
						Reason:             string(operatorv1.ResourceNotReady),
						Message:            "Progressing Installation.operatorv1.tigera.io",
						ObservedGeneration: generation,
					},
					{
						Type:               operatorv1.ComponentDegraded,
						Status:             operatorv1.ConditionTrue,
						Reason:             string(operatorv1.ResourceUpdateError),
						Message:            "Error resolving ImageSet for components",
						ObservedGeneration: generation,
					},
				},
			},
		}
		Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "tigera-secure",
				Generation: 3,
			},
			Spec: operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{
					Count: int64(1),
				},
			},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewTestConditionController(cli, scheme, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		// Expect to be waiting for Elasticsearch and Kibana to be functional
		Expect(result).Should(Equal(reconcile.Result{}))

		By("asserting the finalizers have been set on the LogStorage CR")
		instance := &operatorv1.LogStorage{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(3))

		Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
		Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
		Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
		Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

		Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
		Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.ResourceNotReady)))
		Expect(instance.Status.Conditions[1].Message).To(Equal("Progressing Installation.operatorv1.tigera.io"))
		Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

		Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
		Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.ResourceUpdateError)))
		Expect(instance.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
		Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
	})

	It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
		ts := &operatorv1.TigeraStatus{
			ObjectMeta: metav1.ObjectMeta{Name: "log-storage"},
			Spec:       operatorv1.TigeraStatusSpec{},
			Status: operatorv1.TigeraStatusStatus{
				Conditions: []operatorv1.TigeraStatusCondition{
					{
						Type:               operatorv1.ComponentAvailable,
						Status:             operatorv1.ConditionTrue,
						Reason:             string(operatorv1.AllObjectsAvailable),
						Message:            "All Objects are available",
						ObservedGeneration: generation,
					},
					{
						Type:               operatorv1.ComponentProgressing,
						Status:             operatorv1.ConditionFalse,
						Reason:             string(operatorv1.NotApplicable),
						Message:            "Not Applicable",
						ObservedGeneration: generation,
					},
					{
						Type:               operatorv1.ComponentDegraded,
						Status:             operatorv1.ConditionFalse,
						Reason:             string(operatorv1.NotApplicable),
						Message:            "Not Applicable",
						ObservedGeneration: generation,
					},
				},
			},
		}
		Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "tigera-secure",
				Generation: 3,
			},
			Spec: operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{
					Count: int64(1),
				},
			},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewTestConditionController(cli, scheme, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())

		// Expect to be waiting for Elasticsearch and Kibana to be functional
		Expect(result).Should(Equal(reconcile.Result{}))

		By("asserting the finalizers have been set on the LogStorage CR")
		instance := &operatorv1.LogStorage{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(3))

		Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
		Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
		Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
		Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

		Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
		Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.NotApplicable)))
		Expect(instance.Status.Conditions[1].Message).To(Equal("Not Applicable"))
		Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

		Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
		Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.NotApplicable)))
		Expect(instance.Status.Conditions[2].Message).To(Equal("Not Applicable"))
		Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
	})
})

// CreateLogStorage creates a LogStorage object with the given parameters after filling in defaults,
// and asserts that the creation succeeds.
func CreateLogStorage(client client.Client, ls *operatorv1.LogStorage) {
	// First, simulate the initializing controller being run by filling defaults.
	FillDefaults(ls)

	// Create the LogStorage object.
	ExpectWithOffset(1, client.Create(context.Background(), ls)).ShouldNot(HaveOccurred())
}
