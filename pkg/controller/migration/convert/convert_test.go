package convert

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Parser", func() {
	It("should not detect an installation if none exists", func() {
		c := fake.NewFakeClient()
		p := Converter{c}
		Expect(p.Convert()).To(BeNil())
	})

	It("should detect an installation if one exists", func() {
		c := fake.NewFakeClient(&appsv1.DaemonSet{
			ObjectMeta: v1.ObjectMeta{
				Name:      "calico-node",
				Namespace: "kube-system",
			},
		}, emptyKubeControllerSpec())
		p := Converter{c}
		_, err := p.Convert()
		// though it will detect an install, it will be in the form of an incompatible-cluster error
		Expect(err).To(BeAssignableToTypeOf(ErrIncompatibleCluster{}))
	})

	It("should detect a valid installation", func() {
		c := fake.NewFakeClient(emptyNodeSpec(), emptyKubeControllerSpec())
		p := Converter{c}
		Expect(p.Convert()).ToNot(BeNil())
	})

	It("should error for unchecked env vars", func() {
		node := emptyNodeSpec()
		node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
			Name:  "FOO",
			Value: "bar",
		}}
		c := fake.NewFakeClient(node, emptyKubeControllerSpec())
		p := Converter{c}
		_, err := p.Convert()
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
		p := Converter{c}
		cfg, err := p.Convert()
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
		p := Converter{c}
		_, err := p.Convert()
		Expect(err).To(HaveOccurred())
	})

	// It("should parse cni", func() {
	// 	ds := emptyNodeSpec()
	// 	c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
	// p := Parser{c}
	// 	cfg, err := p.Convert()
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
						Name: "calico-kube-controllers",
					}},
				},
			},
		},
	}
}

func emptyTyphaDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "calico-typha",
			Namespace: "kube-system",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "calico-typha",
					}},
				},
			},
		},
	}
}
