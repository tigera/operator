// Copyright (c) 2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package render_test

import (
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	tigeraPullSecret                      = "tigera-pull-secret"
	calicoNodePrometheusServiceName       = "calico-node-prometheus"
	tigeraPrometheusServiceName           = "tigera-prometheus-api"
	tigeraPrometheusServiceHealthEndpoint = "/health"

	prometheusServiceListenAddrEnvVarName = "LISTEN_ADDR"
	prometheusEndpointUrlEnvVarName       = "PROMETHEUS_ENDPOINT_URL"

	prometheusOperatedHttpServiceUrl       = "http://prometheus-http-api.tigera-prometheus"
	tigeraPrometheusAPIListenPortFieldName = "tigeraPrometheusAPIListenPort"
)

var _ = Describe("Prometheus Service rendering tests", func() {

	var installationSpec *operatorv1.InstallationSpec
	var pullSecrets []*corev1.Secret

	var monitorConfigMap *corev1.ConfigMap
	var expectedResources []struct {
		name    string
		ns      string
		group   string
		version string
		kind    string
	}

	BeforeEach(func() {
		installationSpec = &operatorv1.InstallationSpec{}

		pullSecrets = []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
		}

		monitorConfigMap = createMonitorDefaultConfigMap()

		expectedResources = []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{tigeraPullSecret, common.TigeraPrometheusNamespace, "", "", ""},
			{tigeraPrometheusServiceName, common.OperatorNamespace(), "", "v1", "ConfigMap"},
			{tigeraPrometheusServiceName, "", "policy", "v1beta1", "PodSecurityPolicy"},
			{tigeraPrometheusServiceName, common.TigeraPrometheusNamespace, "apps", "v1", "Deployment"},
			{calicoNodePrometheusServiceName, common.TigeraPrometheusNamespace, "", "v1", "Service"},
		}

	})

	It("should render with default specs", func() {
		prometheusService, err := render.TigeraPrometheusAPI(installationSpec, pullSecrets, nil)

		Expect(err).ToNot(HaveOccurred())
		Expect(prometheusService.ResolveImages(nil)).NotTo(HaveOccurred())

		objectsToCreate, objectsToDelete := prometheusService.Objects()

		Expect(len(objectsToDelete)).To(Equal(0))

		By("veryfying the objects created at render")

		Expect(len(objectsToCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := objectsToCreate[i]
			rtest.ExpectResource(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// check value for each resource object
		for _, object := range objectsToCreate {

			if object.GetName() == tigeraPullSecret {

			} else if object.GetName() == tigeraPrometheusServiceName && object.GetObjectKind().GroupVersionKind().Kind == "Deployment" {
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

	It("should render without PSPs in Openshift", func() {
		installationSpec.KubernetesProvider = operatorv1.ProviderOpenShift

		prometheusService, err := render.TigeraPrometheusAPI(installationSpec, pullSecrets, nil)

		Expect(err).ToNot(HaveOccurred())
		Expect(prometheusService.ResolveImages(nil)).NotTo(HaveOccurred())

		objectsToCreate, objectsToDelete := prometheusService.Objects()

		Expect(len(objectsToDelete)).To(Equal(0))

		By("veryfying the objects created at render")

		// remove PSPs from expected resource
		expectedResources = append(expectedResources[:2], expectedResources[2+1:]...)

		Expect(len(objectsToCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := objectsToCreate[i]
			rtest.ExpectResource(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

	})

	It("should render with specs accordingly when tigeraPrometheusAPIListenPort is specified ", func() {
		prometheusServicePort := 8090
		monitorConfigMap.Data[tigeraPrometheusAPIListenPortFieldName] = strconv.Itoa(prometheusServicePort)

		prometheusService, err := render.TigeraPrometheusAPI(installationSpec, pullSecrets, monitorConfigMap)
		Expect(err).ToNot(HaveOccurred())

		Expect(prometheusService.ResolveImages(nil)).NotTo(HaveOccurred())

		objectsToCreate, objectsToDelete := prometheusService.Objects()

		Expect(len(objectsToDelete)).To(Equal(0))

		By("veryfying the objects created at render")

		expectedResources = append(expectedResources[:1], expectedResources[1+1:]...)
		// -1 because of testing already existing configmap scenario
		Expect(len(objectsToCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := objectsToCreate[i]
			rtest.ExpectResource(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// check value for each resource object
		for _, object := range objectsToCreate {

			if object.GetName() == tigeraPrometheusServiceName && object.GetObjectKind().GroupVersionKind().Kind == "Deployment" {
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
		prometheusService, err := render.TigeraPrometheusAPI(installationSpec, pullSecrets, nil)

		Expect(err).ToNot(HaveOccurred())
		Expect(prometheusService.ResolveImages(nil)).NotTo(HaveOccurred())

		objectsToCreate, objectsToDelete := prometheusService.Objects()

		Expect(len(objectsToDelete)).To(Equal(0))

		By("veryfying the objects created at render")

		Expect(len(objectsToCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := objectsToCreate[i]
			rtest.ExpectResource(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// check value for each resource object
		for _, object := range objectsToCreate {

			if object.GetName() == tigeraPrometheusServiceName && object.GetObjectKind().GroupVersionKind().Kind == "Deployment" {
				tigeraPrometheusServiceDeploymentManifest := object.(*appsv1.Deployment)
				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.HostNetwork).To(BeFalse())
				Expect(tigeraPrometheusServiceDeploymentManifest.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
			}
		}
	})
})

func createMonitorDefaultConfigMap() *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      tigeraPrometheusServiceName,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string]string{
			tigeraPrometheusAPIListenPortFieldName: strconv.Itoa(render.PrometheusDefaultPort),
		},
	}

	return cm
}
