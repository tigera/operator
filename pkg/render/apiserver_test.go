package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("API server rendering tests", func() {
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
				Registry:  "testregistry.com/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
				Components: operatorv1alpha1.ComponentsSpec{
					APIServer: &operatorv1alpha1.APIServerSpec{},
				},
			},
		}

	})

	It("should render an API server with default configuration", func() {
		resources := render.APIServer(instance)

		// Should render the correct resources.
		Expect(len(resources)).To(Equal(9))
		ExpectResource(resources[0], "cnx-apiserver", "kube-system", "", "v1", "Deployment")

		d := resources[0].(*v1.Deployment)

		Expect(d.Name).To(Equal("cnx-apiserver"))
		Expect(len(d.Labels)).To(Equal(2))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Labels).To(HaveKeyWithValue("k8s-app", "cnx-apiserver"))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(1))
		Expect(d.Spec.Strategy.Type).To(Equal(v1.RecreateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Name).To(Equal("cnx-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("kube-system"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(2))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("k8s-app", "cnx-apiserver"))

		Expect(len(d.Spec.Template.Spec.NodeSelector)).To(Equal(1))
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("beta.kubernetes.io/os", "linux"))
		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("cnx-apiserver"))

		expectedTolerations := []corev1.Toleration{
			{Key: "node-role.kubernetes.io/master", Effect: "NoSchedule"},
		}
		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(2))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("cnx-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal("testregistry.com/tigera/cnx-apiserver:test"))

		expectedArgs := []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		}
		Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
		Expect(len(d.Spec.Template.Spec.Containers[0].Env)).To(Equal(1))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom).To(BeNil())

		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(2))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/var/log/calico/audit"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("var-log-calico-audit"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/etc/tigera/audit"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("audit-policy-ee"))

		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Path).To(Equal("/version"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("5443"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.InitialDelaySeconds).To(BeEquivalentTo(90))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(10))

		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext).To(BeNil())

		Expect(d.Spec.Template.Spec.Containers[1].Name).To(Equal("cnx-queryserver"))
		Expect(d.Spec.Template.Spec.Containers[1].Image).To(Equal("testregistry.com/tigera/cnx-queryserver:test"))
		Expect(d.Spec.Template.Spec.Containers[1].Args).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers[1].Env)).To(Equal(2))

		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Name).To(Equal("LOGLEVEL"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Value).To(Equal("info"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].ValueFrom).To(BeNil())

		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts).To(BeEmpty())
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Path).To(Equal("/version"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("8080"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.InitialDelaySeconds).To(BeEquivalentTo(90))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(10))

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(d.Spec.Template.Spec.Volumes[0].Name).To(Equal("var-log-calico-audit"))
		Expect(d.Spec.Template.Spec.Volumes[0].HostPath.Path).To(Equal("/var/log/calico/audit"))
		Expect(*d.Spec.Template.Spec.Volumes[0].HostPath.Type).To(BeEquivalentTo("DirectoryOrCreate"))
		Expect(d.Spec.Template.Spec.Volumes[1].Name).To(Equal("audit-policy-ee"))
		Expect(d.Spec.Template.Spec.Volumes[1].ConfigMap.Name).To(Equal("audit-policy-ee"))
		Expect(d.Spec.Template.Spec.Volumes[1].ConfigMap.Items[0].Key).To(Equal("config"))
		Expect(d.Spec.Template.Spec.Volumes[1].ConfigMap.Items[0].Path).To(Equal("policy.conf"))
		Expect(len(d.Spec.Template.Spec.Volumes[1].ConfigMap.Items)).To(Equal(1))
	})

	It("should render an API server with custom configuration", func() {
		instance.Spec.Components.APIServer = &operatorv1alpha1.APIServerSpec{
			TLS: operatorv1alpha1.TLSConfig{
				Certificate: "crt",
				Key:         "key",
			},
		}

		resources := render.APIServer(instance)

		// Should render the correct resources. One more resource for the secret holding TLS config.
		Expect(len(resources)).To(Equal(10))
		ExpectResource(resources[0], "cnx-apiserver", "kube-system", "", "v1", "Deployment")

		d := resources[0].(*v1.Deployment)

		// One more volume created now for the TLS secret.
		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Volumes[2].Name).To(Equal("apiserver-certs"))
		Expect(d.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal("cnx-apiserver-certs"))

		// And another volume mount for the TLS secret on the API server container.
		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[2].Name).To(Equal("apiserver-certs"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[2].MountPath).To(Equal("/code/apiserver.local.config/certificates"))

		// Verify the secret
		var secret *corev1.Secret
		for _, v := range resources {
			if s, found := v.(*corev1.Secret); found {
				secret = s
				break
			}
		}

		Expect(secret).To(Not(BeNil()))
		Expect(secret.Name).To(Equal("cnx-apiserver-certs"))
		Expect(secret.Namespace).To(Equal("kube-system"))
		Expect(secret.Data).To(HaveKeyWithValue("apiserver.key", []byte("key")))
		Expect(secret.Data).To(HaveKeyWithValue("apiserver.crt", []byte("crt")))
	})
})
