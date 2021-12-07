package utils_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"

	"github.com/tigera/operator/pkg/apis"

	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = FDescribe("", func() {

	const (
		appCN         = "my-app-cn"
		appSecretName = "my-app-tls"
		dbSecretName  = "my-db-tls"
		appNs         = "my-app"
	)

	var (
		cli    client.Client
		scheme *runtime.Scheme

		initContainer corev1.Container
		container     corev1.Container
		volumes       []corev1.Volume
		volumeMounts  []corev1.VolumeMount
		podSpec       corev1.Pod

		certificateManagement *operatorv1.CertificateManagement
		clusterDomain         = "cluster.local"
		appDNSNames           = []string{"my-app"}
	)
	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		Expect(v1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1beta.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		cli = fake.NewFakeClientWithScheme(scheme)

		volumes = []corev1.Volume{}
		volumeMounts = []corev1.VolumeMount{}
		container = corev1.Container{VolumeMounts: volumeMounts}
		initContainer = corev1.Container{VolumeMounts: volumeMounts}

		// A pod that needs to trust "my-db-tls", but needs to present "my-app-tls"
		podSpec = corev1.Pod{
			Spec: corev1.PodSpec{
				Containers:     []corev1.Container{container},
				InitContainers: []corev1.Container{initContainer},
				Volumes:        volumes,
			},
		}

		certificateManagement = &operatorv1.CertificateManagement{CACert: []byte("my-cert")}
	})

	It("Should create a CA & certs if none are present", func() {
		tigeraCA, err := utils.CreateTigeraCA(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		Expect(tigeraCA).NotTo(BeNil())

		// TLS secret to present to other servers.
		appTLS, err := tigeraCA.GetOrCreateCertificate(cli, appCN, appSecretName, appNs, appDNSNames)
		Expect(err).NotTo(HaveOccurred())
		Expect(appTLS).NotTo(BeNil())

		// TLS secret to trust my-db.
		dbTLS, err := tigeraCA.GetOrCreateCertificate(cli, appCN, appSecretName, appNs, appDNSNames)
		Expect(err).NotTo(HaveOccurred())
		Expect(dbTLS).NotTo(BeNil())

		Expect(podSpec).NotTo(BeNil())               // revert.
		Expect(certificateManagement).NotTo(BeNil()) // revert.
	})

})
