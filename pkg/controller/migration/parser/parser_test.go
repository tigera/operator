package parser_test

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/tigera/operator/pkg/controller/migration/parser"
)

var _ = Describe("Parser", func() {
	ctx := context.TODO()

	It("should not detect an installation if none exists", func() {
		c := fake.NewFakeClient()
		Expect(parser.GetExistingInstallation(ctx, c)).To(BeNil())
	})

	It("should detect an installation if one exists", func() {
		c := fake.NewFakeClient(&appsv1.DaemonSet{
			ObjectMeta: v1.ObjectMeta{
				Name:      "calico-node",
				Namespace: "kube-system",
			},
		}, emptyKubeControllerSpec())
		_, err := parser.GetExistingInstallation(ctx, c)
		// though it will detect an install, it will be in the form of an incompatible-cluster error
		Expect(err).To(BeAssignableToTypeOf(parser.ErrIncompatibleCluster{}))
	})

	It("should detect a valid installation", func() {
		c := fake.NewFakeClient(emptyNodeSpec(), emptyKubeControllerSpec())
		Expect(parser.GetExistingInstallation(ctx, c)).ToNot(BeNil())
	})

	It("should error for unchecked env vars", func() {
		node := emptyNodeSpec()
		node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
			Name:  "FOO",
			Value: "bar",
		}}
		c := fake.NewFakeClient(node, emptyKubeControllerSpec())
		_, err := parser.GetExistingInstallation(ctx, c)
		Expect(err).To(HaveOccurred())
	})

	It("should detect an MTU", func() {
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{
			{
				Name:  "CNI_MTU",
				Value: "24",
			},
			{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "mtu": __CNI_MTU__}`,
			},
		}

		c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
		cfg, err := parser.GetExistingInstallation(ctx, c)
		Expect(err).ToNot(HaveOccurred())
		Expect(cfg).ToNot(BeNil())
		exp := int32(24)
		Expect(cfg.Spec.CalicoNetwork.MTU).To(Equal(&exp))
	})

	It("should fail on invalid cni", func() {
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
			Name:  "CNI_NETWORK_CONFIG",
			Value: "{",
		}}

		c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
		_, err := parser.GetExistingInstallation(ctx, c)
		Expect(err).To(HaveOccurred())
	})

	// It("should parse cni", func() {
	// 	ds := emptyNodeSpec()
	// 	c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
	// 	cfg, err := parser.GetExistingInstallation(ctx, c)
	// 	Expect(err).ToNot(HaveOccurred())
	// 	Expect(cfg).ToNot(BeNil())
	// })
})

func emptyNodeSpec() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: v1.ObjectMeta{
			Name:      "calico-node",
			Namespace: "kube-system",
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{
						Name: "install-cni",
						Env: []corev1.EnvVar{{
							Name:  "CNI_NETWORK_CONFIG",
							Value: `{"type": "calico"}`,
						}},
					}},
					Containers: []corev1.Container{{
						Name: "calico-node",
					}},
				},
			},
		},
	}
}

func emptyKubeControllerSpec() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: "kube-system",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "calico-node",
					}},
				},
			},
		},
	}
}
