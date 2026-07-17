// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package waypoint

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Waypoint pull secrets controller tests", func() {
	var (
		cli          client.Client
		scheme       *runtime.Scheme
		ctx          context.Context
		r            *ReconcileWaypointSecrets
		installation *operatorv1.Installation
		istioCR      *operatorv1.Istio
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Create certificate manager prerequisites.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		gatewayWatchReady := &utils.ReadyFlag{}
		gatewayWatchReady.MarkAsReady()

		r = &ReconcileWaypointSecrets{
			Client:            cli,
			scheme:            scheme,
			gatewayWatchReady: gatewayWatchReady,
		}

		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: operatorv1.InstallationSpec{
				Variant: operatorv1.Calico,
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.Calico,
			},
		}

		istioCR = &operatorv1.Istio{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}
	})

	createNamespace := func(name string) {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
		err := cli.Create(ctx, ns)
		if err == nil {
			return
		}
		// Ignore already-exists
		Expect(client.IgnoreAlreadyExists(err)).ShouldNot(HaveOccurred())
	}

	createPullSecret := func(name string) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				".dockerconfigjson": []byte(`{"auths":{"registry.example.com":{"auth":"dGVzdDp0ZXN0"}}}`),
			},
			Type: corev1.SecretTypeDockerConfigJson,
		}
		Expect(cli.Create(ctx, s)).NotTo(HaveOccurred())
	}

	createWaypointGateway := func(name, namespace string) {
		createNamespace(namespace)
		gw := &gapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: gapi.GatewaySpec{
				GatewayClassName: gapi.ObjectName(IstioWaypointClassName),
				Listeners: []gapi.Listener{
					{
						Name:     "mesh",
						Port:     15008,
						Protocol: gapi.ProtocolType("HBONE"),
					},
				},
			},
		}
		Expect(cli.Create(ctx, gw)).NotTo(HaveOccurred())
	}

	createNonWaypointGateway := func(name, namespace string) {
		createNamespace(namespace)
		gw := &gapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: gapi.GatewaySpec{
				GatewayClassName: "some-other-class",
				Listeners: []gapi.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: gapi.HTTPProtocolType,
					},
				},
			},
		}
		Expect(cli.Create(ctx, gw)).NotTo(HaveOccurred())
	}

	doReconcile := func() (reconcile.Result, error) {
		return r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
	}

	listTrackedSecrets := func() []corev1.Secret {
		secretList := &corev1.SecretList{}
		err := cli.List(ctx, secretList, client.MatchingLabels{WaypointPullSecretLabel: "true"})
		Expect(err).NotTo(HaveOccurred())
		return secretList.Items
	}

	listTrackedRoleBindings := func() []rbacv1.RoleBinding {
		rbList := &rbacv1.RoleBindingList{}
		err := cli.List(ctx, rbList, client.MatchingLabels{WaypointPullSecretLabel: "true"})
		Expect(err).NotTo(HaveOccurred())
		return rbList.Items
	}

	createTrackedSecret := func(name, namespace string, owners ...metav1.OwnerReference) {
		createNamespace(namespace)
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       namespace,
				Labels:          map[string]string{WaypointPullSecretLabel: "true"},
				OwnerReferences: owners,
			},
			Type: corev1.SecretTypeDockerConfigJson,
		}
		Expect(cli.Create(ctx, s)).NotTo(HaveOccurred())
	}

	// egwOwnerRef simulates another feature (e.g. egress gateway) holding an owner
	// reference on a shared resource.
	egwOwnerRef := metav1.OwnerReference{
		APIVersion: "operator.tigera.io/v1",
		Kind:       "EgressGateway",
		Name:       "egw",
		UID:        "2222-3333",
	}

	Context("when no pull secrets are configured", func() {
		It("should not create any secrets or RoleBindings", func() {
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			Expect(listTrackedSecrets()).To(BeEmpty())
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})
	})

	Context("when pull secrets are configured", func() {
		BeforeEach(func() {
			createPullSecret("my-pull-secret")
			installation.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
		})

		It("should copy pull secrets to waypoint gateway namespace", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Namespace).To(Equal("user-ns"))
			Expect(secrets[0].Name).To(Equal("my-pull-secret"))
			Expect(secrets[0].Labels[WaypointPullSecretLabel]).To(Equal("true"))
			// The multiple-owners label is a directive to the component handler and
			// must not be persisted.
			Expect(secrets[0].Labels).NotTo(HaveKey(common.MultipleOwnersLabel))
		})

		It("should preserve another controller's owner references on shared pull secret copies", func() {
			// Simulates an egress gateway in the same namespace: it copies the same
			// pull secret and holds owner references on the copy for GC-based cleanup.
			createNamespace("user-ns")
			shared := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "my-pull-secret",
					Namespace:       "user-ns",
					OwnerReferences: []metav1.OwnerReference{egwOwnerRef},
				},
				Type: corev1.SecretTypeDockerConfigJson,
			}
			Expect(cli.Create(ctx, shared)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			got := &corev1.Secret{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "my-pull-secret", Namespace: "user-ns"}, got)).NotTo(HaveOccurred())
			Expect(got.OwnerReferences).To(ConsistOf(egwOwnerRef))
			Expect(got.Labels[WaypointPullSecretLabel]).To(Equal("true"))
			Expect(got.Labels).NotTo(HaveKey(common.MultipleOwnersLabel))
		})

		It("should create a tigera-operator-secrets RoleBinding in the waypoint gateway namespace", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			rbs := listTrackedRoleBindings()
			Expect(rbs).To(HaveLen(1))
			Expect(rbs[0].Namespace).To(Equal("user-ns"))
			Expect(rbs[0].Name).To(Equal(render.TigeraOperatorSecrets))
			Expect(rbs[0].RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rbs[0].RoleRef.Name).To(Equal(render.TigeraOperatorSecrets))
			Expect(rbs[0].Subjects).To(ConsistOf(rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      common.OperatorServiceAccount(),
				Namespace: common.OperatorNamespace(),
			}))
			// The multiple-owners label is a directive to the component handler and
			// must not be persisted.
			Expect(rbs[0].Labels).NotTo(HaveKey(common.MultipleOwnersLabel))
		})

		It("should copy pull secrets only once for multiple gateways in same namespace", func() {
			createWaypointGateway("waypoint-1", "user-ns")
			createWaypointGateway("waypoint-2", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Namespace).To(Equal("user-ns"))
		})

		It("should copy pull secrets to all namespaces with waypoint gateways", func() {
			createWaypointGateway("waypoint-a", "ns-a")
			createWaypointGateway("waypoint-b", "ns-b")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(2))

			namespaces := map[string]bool{}
			for _, s := range secrets {
				namespaces[s.Namespace] = true
			}
			Expect(namespaces).To(HaveKey("ns-a"))
			Expect(namespaces).To(HaveKey("ns-b"))
		})

		It("should clean up stale secrets when gateway is deleted", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listTrackedSecrets()).To(HaveLen(1))

			// Delete the gateway.
			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "waypoint", Namespace: "user-ns"}, gw)).NotTo(HaveOccurred())
			Expect(cli.Delete(ctx, gw)).NotTo(HaveOccurred())

			// Reconcile again.
			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// Secrets and the RoleBinding should be cleaned up in a single reconcile.
			Expect(listTrackedSecrets()).To(BeEmpty())
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})

		It("should clean up labeled secrets in a namespace that has no RoleBinding", func() {
			// Simulates copies left behind from before the controller managed
			// RoleBindings (or created manually): the controller must grant itself
			// access to delete them, then remove that grant again.
			createTrackedSecret("my-pull-secret", "orphan-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			Expect(listTrackedSecrets()).To(BeEmpty())
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})

		It("should not delete stale labeled secrets that another controller owns", func() {
			// A labeled copy carrying owner references is shared with another feature
			// (e.g. egress gateway) that still needs it; cleanup is the GC's job once
			// those owners are gone.
			createTrackedSecret("my-pull-secret", "shared-ns", egwOwnerRef)

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			Expect(listTrackedSecrets()).To(HaveLen(1))
			// Nothing was written or deleted in shared-ns, so no RoleBinding was
			// created there either.
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})

		It("should never delete labeled secrets in reserved namespaces", func() {
			// Copies of pull secrets in these namespaces are managed by other
			// controllers; a stray label must not cause this controller to delete them.
			createTrackedSecret("stray-labeled-secret", common.OperatorNamespace())
			createTrackedSecret("stray-labeled-secret", common.CalicoNamespace)
			createTrackedSecret("stray-labeled-secret", legacyGatewayNamespace)

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			Expect(listTrackedSecrets()).To(HaveLen(3))
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})

		It("should not delete a RoleBinding that another controller owns", func() {
			createNamespace("shared-ns")
			rb := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.TigeraOperatorSecrets,
					Namespace: "shared-ns",
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "gateway.networking.k8s.io/v1",
						Kind:       "Gateway",
						Name:       "envoy-gw",
						UID:        "0000-1111",
					}},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     render.TigeraOperatorSecrets,
				},
				Subjects: []rbacv1.Subject{{
					Kind:      "ServiceAccount",
					Name:      common.OperatorServiceAccount(),
					Namespace: common.OperatorNamespace(),
				}},
			}
			Expect(cli.Create(ctx, rb)).NotTo(HaveOccurred())
			createTrackedSecret("my-pull-secret", "shared-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// The stale secret goes, but the co-owned binding stays for its other owner.
			Expect(listTrackedSecrets()).To(BeEmpty())
			got := &rbacv1.RoleBinding{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: render.TigeraOperatorSecrets, Namespace: "shared-ns"}, got)).NotTo(HaveOccurred())
			Expect(got.OwnerReferences).To(HaveLen(1))
		})

		It("should not take action for non-matching gatewayClassName", func() {
			createNonWaypointGateway("other-gateway", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(BeEmpty())
		})

		It("should clean up old secret when pull secret is renamed", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Name).To(Equal("my-pull-secret"))

			// Change imagePullSecrets from my-pull-secret to new-pull-secret.
			createPullSecret("new-pull-secret")
			inst := &operatorv1.Installation{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, inst)).NotTo(HaveOccurred())
			inst.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "new-pull-secret"},
			}
			Expect(cli.Update(ctx, inst)).NotTo(HaveOccurred())

			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets = listTrackedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Name).To(Equal("new-pull-secret"))
			Expect(secrets[0].Namespace).To(Equal("user-ns"))
		})

		It("should copy multiple pull secrets to waypoint namespace", func() {
			createPullSecret("second-pull-secret")
			inst := &operatorv1.Installation{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, inst)).NotTo(HaveOccurred())
			inst.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
				{Name: "second-pull-secret"},
			}
			Expect(cli.Update(ctx, inst)).NotTo(HaveOccurred())

			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(2))

			names := map[string]bool{}
			for _, s := range secrets {
				names[s.Name] = true
				Expect(s.Namespace).To(Equal("user-ns"))
			}
			Expect(names).To(HaveKey("my-pull-secret"))
			Expect(names).To(HaveKey("second-pull-secret"))
		})

		It("should not copy secrets to the operator namespace", func() {
			createWaypointGateway("waypoint", common.OperatorNamespace())

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// Pull secrets already exist in the operator namespace; the controller
			// should skip it to avoid overwriting source secrets with labeled copies.
			Expect(listTrackedSecrets()).To(BeEmpty())
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})

		It("should not copy secrets to the calico-system namespace", func() {
			createWaypointGateway("waypoint", common.CalicoNamespace)

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// calico-system pull secrets and the tigera-operator-secrets RoleBinding
			// are managed by the installation controller.
			Expect(listTrackedSecrets()).To(BeEmpty())
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})

		It("should not copy secrets to the tigera-gateway namespace", func() {
			createWaypointGateway("waypoint", legacyGatewayNamespace)

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// The gateway API controller's legacy teardown explicitly deletes pull
			// secret copies and the tigera-operator-secrets RoleBinding there;
			// writing copies would fight it.
			Expect(listTrackedSecrets()).To(BeEmpty())
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})
	})

	Context("when Istio CR is deleted", func() {
		It("should clean up all copied secrets", func() {
			createPullSecret("my-pull-secret")
			installation.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listTrackedSecrets()).To(HaveLen(1))
			Expect(listTrackedRoleBindings()).To(HaveLen(1))

			// Delete the Istio CR.
			Expect(cli.Delete(ctx, istioCR)).NotTo(HaveOccurred())

			// Reconcile again.
			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// All secrets and RoleBindings should be cleaned up.
			Expect(listTrackedSecrets()).To(BeEmpty())
			Expect(listTrackedRoleBindings()).To(BeEmpty())
		})
	})

	Context("when Installation resource is missing", func() {
		It("should return gracefully without error", func() {
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("when Gateway watch is not yet ready", func() {
		BeforeEach(func() {
			createPullSecret("my-pull-secret")
			installation.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")
		})

		It("should skip Gateway listing and not create secrets", func() {
			r.gatewayWatchReady = &utils.ReadyFlag{}

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(BeEmpty())
		})

		It("should not treat existing copies as stale", func() {
			// Copy the secrets with the watch ready, then simulate an operator
			// restart where a reconcile fires before the watch is re-established.
			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listTrackedSecrets()).To(HaveLen(1))
			Expect(listTrackedRoleBindings()).To(HaveLen(1))

			r.gatewayWatchReady = &utils.ReadyFlag{}

			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			Expect(listTrackedSecrets()).To(HaveLen(1))
			Expect(listTrackedRoleBindings()).To(HaveLen(1))
		})
	})
})
