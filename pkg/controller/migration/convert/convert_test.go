package convert

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Parser", func() {
	var ctx = context.Background()

	It("should not detect an installation if none exists", func() {
		c := fake.NewFakeClient()
		Expect(Convert(ctx, c, &operatorv1.Installation{})).To(BeNil())
	})

	It("should detect an installation if one exists", func() {
		c := fake.NewFakeClient(&appsv1.DaemonSet{
			ObjectMeta: v1.ObjectMeta{
				Name:      "calico-node",
				Namespace: "kube-system",
			},
		}, emptyKubeControllerSpec())
		err := Convert(ctx, c, &operatorv1.Installation{})
		// though it will detect an install, it will be in the form of an incompatible-cluster error
		Expect(err).To(BeAssignableToTypeOf(ErrIncompatibleCluster{}))
	})

	It("should detect a valid installation", func() {
		c := fake.NewFakeClient(emptyNodeSpec(), emptyKubeControllerSpec())
		Expect(Convert(ctx, c, &operatorv1.Installation{})).To(BeNil())
	})

	It("should error if it detects a canal installation", func() {
		c := fake.NewFakeClient(&appsv1.DaemonSet{
			ObjectMeta: v1.ObjectMeta{
				Name:      "canal-node",
				Namespace: "kube-system",
			},
		})
		Expect(Convert(ctx, c, &operatorv1.Installation{})).To(HaveOccurred())
	})

	It("should error for unchecked env vars", func() {
		node := emptyNodeSpec()
		node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
			Name:  "FOO",
			Value: "bar",
		}}
		c := fake.NewFakeClient(node, emptyKubeControllerSpec())
		err := Convert(ctx, c, &operatorv1.Installation{})
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
		err := Convert(ctx, c, cfg)
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
		err := Convert(ctx, c, &operatorv1.Installation{})
		Expect(err).To(HaveOccurred())
	})

	// It("should parse cni", func() {
	// 	ds := emptyNodeSpec()
	// 	c := fake.NewFakeClient(ds, emptyKubeControllerSpec())

	// 	cfg, err := Convert(ctx, c, &operatorv1.Installation{})
	// 	Expect(err).ToNot(HaveOccurred())
	// 	Expect(cfg).ToNot(BeNil())
	// })
	Describe("handle Node metrics port migration", func() {
		It("defaults prometheus off when no prometheus environment variables set", func() {
			ds := emptyNodeSpec()

			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, cfg)
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
			err := Convert(ctx, c, cfg)
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
			err := Convert(ctx, c, cfg)
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
			err := Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(*cfg.Spec.NodeMetricsPort).To(Equal(int32(7777)))
		})
	})
	Describe("handle alternate CNI migration", func() {
		DescribeTable("non-calico plugins", func(envs []corev1.EnvVar, plugin operatorv1.CNIPluginType) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers = nil
			ds.Spec.Template.Spec.Containers[0].Env = append(envs, corev1.EnvVar{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			})

			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(plugin))
		},
			Entry("AzureVNET", []corev1.EnvVar{{Name: "FELIX_INTERFACEPREFIX", Value: "avz"}}, operatorv1.PluginAzureVNET),
			Entry("AmazonVPC", []corev1.EnvVar{
				{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
				{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
			}, operatorv1.PluginAmazonVPC),
			Entry("GKE", []corev1.EnvVar{
				{Name: "FELIX_INTERFACEPREFIX", Value: "gke"},
				{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
				{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"},
			}, operatorv1.PluginGKE),
		)
		It("should convert AWS CNI install", func() {
			c := fake.NewFakeClient(awsCNIPolicyOnlyConfig()...)
			err := Convert(ctx, c, &operatorv1.Installation{})
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
					Tolerations: []corev1.Toleration{
						{
							Effect:   corev1.TaintEffectNoSchedule,
							Operator: corev1.TolerationOpExists,
						},
						{
							Key:      "CriticalAddonsOnly",
							Operator: corev1.TolerationOpExists,
						},
						{
							Effect:   corev1.TaintEffectNoExecute,
							Operator: corev1.TolerationOpExists,
						},
					},
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
					Volumes: []corev1.Volume{
						{
							Name: "lib-modules",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
						{
							Name: "var-run-calico",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/calico",
								},
							},
						},
						{
							Name: "var-lib-calico",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/calico",
								},
							},
						},
						{
							Name: "xtables-lock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/run/xtables.lock",
								},
							},
						},
						{
							Name: "cni-bin-dir",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/opt/cni/bin",
								},
							},
						},
						{
							Name: "cni-net-dir",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/cni/net.d",
								},
							},
						},
					},
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
					Tolerations: []corev1.Toleration{
						{
							Key:      "CriticalAddonsOnly",
							Operator: corev1.TolerationOpExists,
						},
						{
							Effect: corev1.TaintEffectNoSchedule,
							Key:    "node-role.kubernetes.io/master",
						},
					},
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
					Tolerations: []corev1.Toleration{{
						Key:      "CriticalAddonsOnly",
						Operator: corev1.TolerationOpExists,
					}},
					Containers: []corev1.Container{{
						Name: "calico-typha",
					}},
				},
			},
		},
	}
}

// emptyComponents is a convenience function for initializing a
// components object which meets basic validation requirements.
func emptyComponents() components {
	return components{
		node: CheckedDaemonSet{
			*emptyNodeSpec(),
			make(map[string]checkedFields),
		},
		kubeControllers: emptyKubeControllerSpec(),
		typha:           emptyTyphaDeployment(),
	}
}
