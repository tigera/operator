package convert_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/migration/convert"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Parser", func() {
	var ctx = context.Background()

	It("should not detect an installation if none exists", func() {
		c := fake.NewFakeClient()
		Expect(convert.Convert(ctx, c, &operatorv1.Installation{})).To(BeNil())
	})

	It("should detect an installation if one exists", func() {
		c := fake.NewFakeClient(&appsv1.DaemonSet{
			ObjectMeta: v1.ObjectMeta{
				Name:      "calico-node",
				Namespace: "kube-system",
			},
		}, emptyKubeControllerSpec())
		err := convert.Convert(ctx, c, &operatorv1.Installation{})
		// though it will detect an install, it will be missing the calico-node container
		Expect(err).To(BeAssignableToTypeOf(convert.ErrContainerNotFound{}))
	})

	It("should detect a valid installation", func() {
		c := fake.NewFakeClient(emptyNodeSpec(), emptyKubeControllerSpec())
		Expect(convert.Convert(ctx, c, &operatorv1.Installation{})).To(BeNil())
	})

	It("should error for unchecked env vars", func() {
		node := emptyNodeSpec()
		node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
			Name:  "FOO",
			Value: "bar",
		}}
		c := fake.NewFakeClient(node, emptyKubeControllerSpec())
		err := convert.Convert(ctx, c, &operatorv1.Installation{})
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
		cfg := &operatorv1.Installation{}
		err := convert.Convert(ctx, c, cfg)
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
		err := convert.Convert(ctx, c, &operatorv1.Installation{})
		Expect(err).To(HaveOccurred())
	})

	// It("should parse cni", func() {
	// 	ds := emptyNodeSpec()
	// 	c := fake.NewFakeClient(ds, emptyKubeControllerSpec())

	// 	cfg, err := convert.Convert(ctx, c, &operatorv1.Installation{})
	// 	Expect(err).ToNot(HaveOccurred())
	// 	Expect(cfg).ToNot(BeNil())
	// })
	Describe("handle Node metrics port migration", func() {
		It("defaults prometheus off when no prometheus environment variables set", func() {
			ds := emptyNodeSpec()

			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := convert.Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.NodeMetricsPort).To(BeNil())
		})
		It("with metrics enabled the default port is used", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "FELIX_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}}

			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := convert.Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(*cfg.Spec.NodeMetricsPort).To(Equal(int32(9091)))
		})
		It("with metrics port env var only, metrics are still disabled", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "FELIX_PROMETHEUSMETRICSPORT",
				Value: "5555",
			}}

			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := convert.Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.NodeMetricsPort).To(BeNil())
		})
		It("with metrics port and enabled is reflected in installation", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "FELIX_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}, {
				Name:  "FELIX_PROMETHEUSMETRICSPORT",
				Value: "7777",
			}}

			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := convert.Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(*cfg.Spec.NodeMetricsPort).To(Equal(int32(7777)))
		})
	})
	Describe("handle alternate CNI migration", func() {
		It("should convert AWS CNI install", func() {
			c := fake.NewFakeClient(awsCNIPolicyOnlyConfig()...)
			err := convert.Convert(ctx, c, &operatorv1.Installation{})
			Expect(err).NotTo(HaveOccurred())
		})
	})
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
