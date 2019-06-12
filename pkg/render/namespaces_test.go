package render_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Namespace rendering tests", func() {
	var instance *operatorv1alpha1.Core
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1alpha1.Core{
			Spec: operatorv1alpha1.CoreSpec{
				IPPools: []operatorv1alpha1.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Version:   "test",
				Registry:  "test-reg/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
				Components: operatorv1alpha1.ComponentsSpec{
					KubeProxy: operatorv1alpha1.KubeProxySpec{
						Required:  true,
						APIServer: "https://apiserver:443",
						Image:     "k8s.gcr.io/kube-proxy:v1.13.6",
					},
				},
			},
		}

	})

	It("should render a namespace", func() {
		resources := render.Namespaces(instance)
		Expect(len(resources)).To(Equal(1))
		ExpectResource(resources[0], "calico-system", "", "", "v1", "Namespace")
		meta := resources[0].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("calico-system"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))
	})

	It("should render an additional namespace if this is Tigera Secure", func() {
		instance.Spec.Variant = operatorv1alpha1.TigeraSecureEnterprise
		resources := render.Namespaces(instance)
		Expect(len(resources)).To(Equal(2))
		ExpectResource(resources[0], "calico-system", "", "", "v1", "Namespace")
		meta := resources[0].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("calico-system"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))

		ExpectResource(resources[1], "tigera-system", "", "", "v1", "Namespace")
		meta = resources[1].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("tigera-system"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))
	})

	It("should render a namespace for openshift", func() {
		os.Setenv("OPENSHIFT", "true")
		defer os.Unsetenv("OPENSHIFT")
		resources := render.Namespaces(instance)
		Expect(len(resources)).To(Equal(1))
		ExpectResource(resources[0], "calico-system", "", "", "v1", "Namespace")
		meta := resources[0].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()["openshift.io/run-level"]).To(Equal("0"))
		Expect(meta.GetAnnotations()["openshift.io/node-selector"]).To(Equal(""))
	})
})
