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

package render

import (
	"net/url"
	"strconv"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	calicoNodePrometheusServiceName = "calico-node-prometheus"

	tigeraPrometheusAPIName             = "tigera-prometheus-api"
	prometheusEndpointUrlEnvVarName     = "PROMETHEUS_ENDPOINT_URL"
	prometheusOperatedHttpServiceScheme = "http"
	prometheusOperatedHttpServiceHost   = PrometheusHTTPAPIServiceName + ".tigera-prometheus"

	prometheusServiceListenAddrEnvVarName = "LISTEN_ADDR"

	tigeraPrometheusServiceHealthEndpoint = "/health"
)

func TigeraPrometheusAPI(cr *operator.InstallationSpec, pullSecrets []*corev1.Secret, prometheusServicePort int) Component {

	if prometheusServicePort <= 0 {
		prometheusServicePort = PrometheusDefaultPort
	}

	return &tigeraPrometheusAPIComponent{
		installation:          cr,
		pullSecrets:           pullSecrets,
		prometheusServicePort: prometheusServicePort,
	}
}

type tigeraPrometheusAPIComponent struct {
	installation           *operator.InstallationSpec
	pullSecrets            []*corev1.Secret
	prometheusServicePort  int
	prometheusServiceImage string
}

func (p *tigeraPrometheusAPIComponent) ResolveImages(is *operator.ImageSet) error {
	reg := p.installation.Registry
	path := p.installation.ImagePath
	prefix := p.installation.ImagePrefix

	prometheusServiceImage, err := components.GetReference(components.ComponentTigeraPrometheusService, reg, path, prefix, is)
	if err != nil {
		return err
	}

	p.prometheusServiceImage = prometheusServiceImage

	return nil
}

// Objects returns the lists of objects in this component that should be created and/or deleted during
// rendering.
func (p *tigeraPrometheusAPIComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	// tigera-prometheus-objects
	namespacedObjects := []client.Object{}

	// place pullsecrets secrets under tigera-prometheus
	secrets := secret.CopyToNamespace(common.TigeraPrometheusNamespace, p.pullSecrets...)
	namespacedObjects = append(namespacedObjects, secret.ToRuntimeObjects(secrets...)...)

	namespacedObjects = append(
		namespacedObjects,
		p.tigeraPrometheusApiPodSecurityPolicy(),
		p.tigeraPrometheusServiceDeployment(),
		p.calicoNodePrometheusService(),
	)

	objsToCreate = []client.Object{}
	objsToCreate = append(objsToCreate, namespacedObjects...)

	objsToDelete = []client.Object{}

	return objsToCreate, objsToDelete

}

func (p *tigeraPrometheusAPIComponent) Ready() bool {
	return true
}

func (p *tigeraPrometheusAPIComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

// calicoNodePrometheusService sets up a service for the Prometheus Service/Proxy deployment
func (p *tigeraPrometheusAPIComponent) calicoNodePrometheusService() *corev1.Service {

	s := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      calicoNodePrometheusServiceName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"k8s-app": tigeraPrometheusAPIName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "web",
					Port:       PrometheusDefaultPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(p.prometheusServicePort),
				},
			},
		},
	}

	return s
}

// tigeraPrometheusServiceDeployment deployment for the Prometheus Service/Proxy pod and image
func (p *tigeraPrometheusAPIComponent) tigeraPrometheusServiceDeployment() *appsv1.Deployment {
	var replicas int32 = 1
	podDnsPolicy := corev1.DNSClusterFirst
	podHostNetworked := false

	// set to host networked if cluster is on EKS using Calico CNI since the EKS managed Kubernetes APIserver
	// cannot reach the pod network in this configuration. This is because Calico cannot manage
	// the managed control plane nodes' network
	if p.installation.KubernetesProvider == operator.ProviderEKS &&
		p.installation.CNI.Type == operator.PluginCalico {
		podHostNetworked = true
		// corresponding dns policy for hostnetwoked pods to resolve the service hostname urls
		podDnsPolicy = corev1.DNSClusterFirstWithHostNet
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      tigeraPrometheusAPIName,
			Namespace: common.TigeraPrometheusNamespace,
			Labels: map[string]string{
				"k8s-app": tigeraPrometheusAPIName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": tigeraPrometheusAPIName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tigeraPrometheusAPIName,
					Namespace: common.TigeraPrometheusNamespace,
					Labels: map[string]string{
						"k8s-app": tigeraPrometheusAPIName,
					},
				},
				Spec: corev1.PodSpec{
					DNSPolicy:        podDnsPolicy,
					HostNetwork:      podHostNetworked,
					ImagePullSecrets: secret.GetReferenceList(p.pullSecrets),
					NodeSelector:     p.installation.ControlPlaneNodeSelector,
					Tolerations:      []corev1.Toleration{rmeta.TolerateMaster},
					Containers: []corev1.Container{
						p.prometheusServiceContainers(),
					},
				},
			},
		},
	}

	return d
}

func (p *tigeraPrometheusAPIComponent) tigeraPrometheusApiPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(tigeraPrometheusAPIName)
	return psp
}

func (p *tigeraPrometheusAPIComponent) prometheusServiceContainers() corev1.Container {
	prometheusOperatedHttpUrl := url.URL{
		Scheme: prometheusOperatedHttpServiceScheme,
		Host:   prometheusOperatedHttpServiceHost + ":" + strconv.Itoa(PrometheusDefaultPort),
	}

	prometheusServiceListenAddrValue := ":" + strconv.Itoa(p.prometheusServicePort)

	c := corev1.Container{
		Name:            tigeraPrometheusAPIName,
		Image:           p.prometheusServiceImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: int32(p.prometheusServicePort),
			},
		},
		Env: []corev1.EnvVar{
			{
				Name:  prometheusServiceListenAddrEnvVarName,
				Value: prometheusServiceListenAddrValue,
			},
			{
				Name:  prometheusEndpointUrlEnvVarName,
				Value: prometheusOperatedHttpUrl.String(),
			},
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: tigeraPrometheusServiceHealthEndpoint,
					Port: intstr.FromInt(p.prometheusServicePort),
				},
			},
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: tigeraPrometheusServiceHealthEndpoint,
					Port: intstr.FromInt(p.prometheusServicePort),
				},
			},
		},
	}

	return c
}
