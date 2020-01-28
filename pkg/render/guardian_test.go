package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Rendering tests", func() {
	var g render.Component
	var resources []runtime.Object

	BeforeEach(func() {
		addr := "127.0.0.1:1234"
		secret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.GuardianSecretName,
				Namespace: render.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"cert": []byte("foo"),
				"key":  []byte("bar"),
			},
		}
		g = render.Guardian(
			addr,
			[]*corev1.Secret{},
			false,
			"my-reg/",
			secret,
		)
		resources = g.Objects()
	})

	It("should render all resources for a managed cluster", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: render.GuardianNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.GuardianServiceAccountName, ns: render.GuardianNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.GuardianClusterRoleName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.GuardianClusterRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.GuardianDeploymentName, ns: render.GuardianNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: render.GuardianServiceName, ns: render.GuardianNamespace, group: "", version: "", kind: ""},
			{name: render.GuardianSecretName, ns: render.GuardianNamespace, group: "", version: "v1", kind: "Secret"},
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))
		for i, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		deployment := resources[4].(*appsv1.Deployment)
		Expect(deployment.Spec.Template.Spec.Containers[0].Image).Should(Equal("my-reg/tigera/guardian:" + components.VersionGuardian))
	})

})
