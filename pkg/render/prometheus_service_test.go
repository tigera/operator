package render_test

import (
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	tigeraPullSecret                      = "tigera-pull-secret"
	calicoNodePrometheusServiceName       = "calico-node-prometheus"
	tigeraPrometheusServiceName           = "tigera-prometheus-service"
	tigeraPrometheusServiceHealthEndpoint = "/health"

	prometheusServiceListenAddrEnvVarName = "LISTEN_ADDR"
	prometheusEndpointUrlEnvVarName       = "PROMETHEUS_ENDPOINT_URL"

	prometheusOperatedHttpServiceUrl = "http://prometheus-operated-http.tigera-prometheus"
)

var _ = Describe("Prometheus Service rendering tests", func() {

	var installationSpec *operatorv1.InstallationSpec
	var pullSecrets []*corev1.Secret
	var prometheusServicePort int

	BeforeEach(func() {
		installationSpec = &operatorv1.InstallationSpec{}
		pullSecrets = []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
		}

		// set to 9 to trigger applying default port 9090
		prometheusServicePort = 0
	})

	It("should render with default specs", func() {
		prometheusService := render.TigeraPrometheusService(installationSpec, pullSecrets, prometheusServicePort)

		Expect(prometheusService.ResolveImages(nil)).NotTo(HaveOccurred())

		objectsToCreate, objectsToDelete := prometheusService.Objects()

		Expect(len(objectsToDelete)).To(Equal(0))

		By("veryfying the objects created at render")

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{tigeraPullSecret, common.TigeraPrometheusNamespace, "", "", ""},
			{tigeraPrometheusServiceName, common.TigeraPrometheusNamespace, "", "v1", "Deployment"},
			{calicoNodePrometheusServiceName, common.TigeraPrometheusNamespace, "", "v1", "Service"},
		}

		Expect(len(objectsToCreate)).To(Equal(len(expectedResources)))

		// check value for each resource object
		for _, object := range objectsToCreate {

			if object.GetName() == tigeraPullSecret {

			} else if object.GetName() == tigeraPrometheusServiceName {
				tigeraPrometheusServiceDeploymentManifest := object.(*appsv1.Deployment)

				Expect(tigeraPrometheusServiceDeploymentManifest.GetLabels()["k8s-app"]).To(Equal(tigeraPrometheusServiceName))

				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Selector.MatchLabels["k8s-app"]).To(Equal(tigeraPrometheusServiceName))

				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.ObjectMeta.Name).To(Equal(tigeraPrometheusServiceName))
				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.ObjectMeta.Namespace).To(Equal(common.TigeraPrometheusNamespace))
				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.ObjectMeta.Labels["k8s-app"]).To(Equal(tigeraPrometheusServiceName))
				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.HostNetwork).To(BeFalse())
				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirst))

				// validate container specs
				Expect(len(tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.Containers)).To(Equal(1))
				tigeraPrometheusServiceDeploymentContainerTemplate := tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.Containers[0]

				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.Name).To(Equal(tigeraPrometheusServiceName))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.Ports[0].ContainerPort).To(Equal(int32(render.PrometheusDefaultPort)))
				Expect(len(tigeraPrometheusServiceDeploymentContainerTemplate.Env)).To(Equal(2))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.Env).To(ContainElements(
					corev1.EnvVar{
						Name:  prometheusServiceListenAddrEnvVarName,
						Value: ":" + strconv.Itoa(render.PrometheusDefaultPort),
					},
					corev1.EnvVar{
						Name:  prometheusEndpointUrlEnvVarName,
						Value: prometheusOperatedHttpServiceUrl + ":" + strconv.Itoa(render.PrometheusDefaultPort),
					},
				))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.ReadinessProbe.HTTPGet.Path).To(Equal(tigeraPrometheusServiceHealthEndpoint))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.ReadinessProbe.HTTPGet.Port.IntVal).To(Equal(int32(render.PrometheusDefaultPort)))

				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.LivenessProbe.HTTPGet.Path).To(Equal(tigeraPrometheusServiceHealthEndpoint))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.LivenessProbe.HTTPGet.Port.IntVal).To(Equal(int32(render.PrometheusDefaultPort)))

			} else if object.GetName() == calicoNodePrometheusServiceName {
				calicoNodePrometheusServiceManifest := object.(*corev1.Service)
				Expect(calicoNodePrometheusServiceManifest.Spec.Selector["k8s-app"]).To(Equal(tigeraPrometheusServiceName))

				Expect(calicoNodePrometheusServiceManifest.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
				Expect(len(calicoNodePrometheusServiceManifest.Spec.Ports)).To(Equal(1))
				Expect(calicoNodePrometheusServiceManifest.Spec.Ports[0].Port).To(Equal(int32(render.PrometheusDefaultPort)))
				// default if not set from monitor spec
				Expect(calicoNodePrometheusServiceManifest.Spec.Ports[0].TargetPort.IntVal).To(Equal(int32(render.PrometheusDefaultPort)))
			}
		}
	})

	It("should render with specs accordingly when prometheuServicePort is specified ", func() {
		prometheusServicePort = 8090
		prometheusService := render.TigeraPrometheusService(installationSpec, pullSecrets, prometheusServicePort)

		Expect(prometheusService.ResolveImages(nil)).NotTo(HaveOccurred())

		objectsToCreate, objectsToDelete := prometheusService.Objects()

		Expect(len(objectsToDelete)).To(Equal(0))

		By("veryfying the objects created at render")

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{tigeraPullSecret, common.TigeraPrometheusNamespace, "", "", ""},
			{tigeraPrometheusServiceName, common.TigeraPrometheusNamespace, "", "v1", "Deployment"},
			{calicoNodePrometheusServiceName, common.TigeraPrometheusNamespace, "", "v1", "Service"},
		}

		Expect(len(objectsToCreate)).To(Equal(len(expectedResources)))

		// check value for each resource object
		for _, object := range objectsToCreate {

			if object.GetName() == tigeraPrometheusServiceName {
				tigeraPrometheusServiceDeploymentManifest := object.(*appsv1.Deployment)

				// validate container specs
				Expect(len(tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.Containers)).To(Equal(1))
				tigeraPrometheusServiceDeploymentContainerTemplate := tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.Containers[0]

				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.Name).To(Equal(tigeraPrometheusServiceName))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.Ports[0].ContainerPort).To(Equal(int32(prometheusServicePort)))
				Expect(len(tigeraPrometheusServiceDeploymentContainerTemplate.Env)).To(Equal(2))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.Env).To(ContainElements(
					corev1.EnvVar{
						Name:  prometheusServiceListenAddrEnvVarName,
						Value: ":" + strconv.Itoa(prometheusServicePort),
					},
					corev1.EnvVar{
						Name:  prometheusEndpointUrlEnvVarName,
						Value: prometheusOperatedHttpServiceUrl + ":" + strconv.Itoa(render.PrometheusDefaultPort),
					},
				))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.ReadinessProbe.HTTPGet.Path).To(Equal(tigeraPrometheusServiceHealthEndpoint))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.ReadinessProbe.HTTPGet.Port.IntVal).To(Equal(int32(prometheusServicePort)))

				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.LivenessProbe.HTTPGet.Path).To(Equal(tigeraPrometheusServiceHealthEndpoint))
				Expect(tigeraPrometheusServiceDeploymentContainerTemplate.LivenessProbe.HTTPGet.Port.IntVal).To(Equal(int32(prometheusServicePort)))

			} else if object.GetName() == calicoNodePrometheusServiceName {
				calicoNodePrometheusServiceManifest := object.(*corev1.Service)

				Expect(len(calicoNodePrometheusServiceManifest.Spec.Ports)).To(Equal(1))
				Expect(calicoNodePrometheusServiceManifest.Spec.Ports[0].Port).To(Equal(int32(render.PrometheusDefaultPort)))
				// default if not set from monitor spec
				Expect(calicoNodePrometheusServiceManifest.Spec.Ports[0].TargetPort.IntVal).To(Equal(int32(prometheusServicePort)))
			}
		}
	})

	It("should render pods as hostnetworked and hostNet dnsPolicy", func() {
		prometheusService := render.TigeraPrometheusService(installationSpec, pullSecrets, prometheusServicePort)

		Expect(prometheusService.ResolveImages(nil)).NotTo(HaveOccurred())

		objectsToCreate, objectsToDelete := prometheusService.Objects()

		Expect(len(objectsToDelete)).To(Equal(0))

		By("veryfying the objects created at render")

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{tigeraPullSecret, common.TigeraPrometheusNamespace, "", "", ""},
			{tigeraPrometheusServiceName, common.TigeraPrometheusNamespace, "", "v1", "Deployment"},
			{calicoNodePrometheusServiceName, common.TigeraPrometheusNamespace, "", "v1", "Service"},
		}

		Expect(len(objectsToCreate)).To(Equal(len(expectedResources)))

		// check value for each resource object
		for _, object := range objectsToCreate {

			if object.GetName() == tigeraPrometheusServiceName {
				tigeraPrometheusServiceDeploymentManifest := object.(*appsv1.Deployment)
				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.HostNetwork).To(BeFalse())
				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
			}
		}
	})

})
