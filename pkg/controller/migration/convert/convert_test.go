package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Parser", func() {
	var ctx = context.Background()
	var pool *crdv1.IPPool
	var scheme *runtime.Scheme
	BeforeEach(func() {
		scheme = kscheme.Scheme
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		pool = crdv1.NewIPPool()
		pool.Spec = crdv1.IPPoolSpec{
			CIDR:        "192.168.4.0/24",
			IPIPMode:    crdv1.IPIPModeAlways,
			NATOutgoing: true,
		}
	})

	It("should not detect an installation if none exists", func() {
		c := fake.NewFakeClientWithScheme(scheme)
		Expect(Convert(ctx, c, &operatorv1.Installation{})).To(BeNil())
	})

	It("should detect an installation if one exists", func() {
		c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig())
		err := Convert(ctx, c, &operatorv1.Installation{})
		Expect(err).ToNot(HaveOccurred())
	})

	It("should detect a valid installation", func() {
		c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig())
		Expect(Convert(ctx, c, &operatorv1.Installation{})).To(BeNil())
	})

	It("should error if it detects a canal installation", func() {
		c := fake.NewFakeClientWithScheme(scheme, &appsv1.DaemonSet{
			ObjectMeta: v1.ObjectMeta{
				Name:      "canal-node",
				Namespace: "kube-system",
			},
		}, pool, emptyFelixConfig())
		Expect(Convert(ctx, c, &operatorv1.Installation{})).To(HaveOccurred())
	})

	It("should error for unchecked env vars", func() {
		node := emptyNodeSpec()
		node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
			Name:  "FOO",
			Value: "bar",
		}}
		c := fake.NewFakeClientWithScheme(scheme, node, emptyKubeControllerSpec(), pool, emptyFelixConfig())
		err := Convert(ctx, c, &operatorv1.Installation{})
		Expect(err).To(HaveOccurred())
	})

	It("should detect an MTU via substitution", func() {
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{
			{
				Name:  "CNI_MTU",
				Value: "24",
			},
			{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam":{"type":"calico-ipam"}, "mtu": __CNI_MTU__}`,
			},
		}

		c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
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

		c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
		err := Convert(ctx, c, &operatorv1.Installation{})
		Expect(err).To(HaveOccurred())
	})

	Context("CNI", func() {
		var _ = Describe("CNI", func() {
			It("should load cni from correct fields on calico-node", func() {
				ds := emptyNodeSpec()
				ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{
					{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
							"name": "k8s-pod-network",
							"cniVersion": "0.3.1",
							"plugins": [
							  {
								"type": "calico",
								"log_level": "info",
								"datastore_type": "kubernetes",
								"nodename": "__KUBERNETES_NODE_NAME__",
								"mtu": __CNI_MTU__,
								"ipam": {"type": "calico-ipam"},
								"policy": {
									"type": "k8s"
								},
								"kubernetes": {
									"kubeconfig": "__KUBECONFIG_FILEPATH__"
								}
							  }
							]
						}`,
					},
				}

				cli := fake.NewFakeClient(ds, emptyKubeControllerSpec())
				c := components{
					node: CheckedDaemonSet{
						DaemonSet:   *ds,
						checkedVars: map[string]checkedFields{},
					},
					client: cli,
				}

				nc, err := loadCNI(&c)
				Expect(err).ToNot(HaveOccurred())
				Expect(nc.CalicoConfig).ToNot(BeNil())
				Expect(nc.CalicoConfig.IPAM.Type).To(Equal("calico-ipam"), fmt.Sprintf("Got %+v", c.cni.CalicoConfig))
			})
		})
	})
})
