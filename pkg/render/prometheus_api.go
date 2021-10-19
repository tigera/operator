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
	"fmt"
	"net/url"
	"strconv"

	operatorv1 "github.com/tigera/operator/api/v1"
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
	TigeraPrometheusAPIName = "tigera-prometheus-api"

	calicoNodePrometheusServiceName = "calico-node-prometheus"

	prometheusEndpointUrlEnvVarName     = "PROMETHEUS_ENDPOINT_URL"
	prometheusOperatedHttpServiceScheme = "http"
	prometheusOperatedHttpServiceHost   = PrometheusHTTPAPIServiceName + ".tigera-prometheus"

	prometheusServiceListenAddrEnvVarName = "LISTEN_ADDR"

	tigeraPrometheusServiceHealthEndpoint = "/health"

	// pod listens to and the TargetPort of calico-node-prometheus service.
	// If not set it defaults to port 9090. In the scenario that the cluster
	// is hosted on EKS and using Calico as it's CNI, tigera-prometheus-service
	// will be HostNetwoked. This is configurable in the configMap passed to TigeraPrometheusAPI
	tigeraPrometheusAPIListenPortFieldName = "tigeraPrometheusAPIListenPort"
)

func TigeraPrometheusAPI(cr *operatorv1.InstallationSpec, pullSecrets []*corev1.Secret, configMap *corev1.ConfigMap) (Component, error) {

	return &tigeraPrometheusAPIComponent{
		configMap:    configMap,
		installation: cr,
		pullSecrets:  pullSecrets,
	}, nil
}

type tigeraPrometheusAPIComponent struct {
	configMap              *corev1.ConfigMap
	installation           *operatorv1.InstallationSpec
	pullSecrets            []*corev1.Secret
	prometheusServiceImage string
}

func (p *tigeraPrometheusAPIComponent) ResolveImages(is *operatorv1.ImageSet) error {
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

	tigeraPrometheusApiConfigMap := p.configMap

	if tigeraPrometheusApiConfigMap == nil {
		tigeraPrometheusApiConfigMap = p.getDefaultConfigMap()
		namespacedObjects = append(namespacedObjects, tigeraPrometheusApiConfigMap)
	}

	configuredTigeraPrometheusApiPort, err := strconv.Atoi(tigeraPrometheusApiConfigMap.Data[tigeraPrometheusAPIListenPortFieldName])

	if err != nil {
		log.Error(err, fmt.Sprintf("incorrect listen port value for %s, defaulting to port: %d", TigeraPrometheusAPIName, PrometheusDefaultPort))
		configuredTigeraPrometheusApiPort = PrometheusDefaultPort
	}

	// openshift will use the default restricted SCCs if one is not provided
	if p.installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		namespacedObjects = append(namespacedObjects, p.podSecurityPolicy())
	}

	namespacedObjects = append(
		namespacedObjects,
		p.deployment(configuredTigeraPrometheusApiPort),
		p.calicoNodePrometheusService(configuredTigeraPrometheusApiPort),
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

// podSecurityPolicy PSP for tigera-prometheus-api
func (p *tigeraPrometheusAPIComponent) podSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(TigeraPrometheusAPIName)
	return psp
}

// calicoNodePrometheusService sets up a service for the Prometheus Service/Proxy deployment
func (p *tigeraPrometheusAPIComponent) calicoNodePrometheusService(prometheusServiceListenPort int) *corev1.Service {
	// Note: name (calico-node-prometheus) used in this service is matching the name that was previously being created
	// for the prometheus instance now that we're replacing to inject a proxy in the chain and we're keeping the name
	// the same as before for version skew compatibility

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
				"k8s-app": TigeraPrometheusAPIName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "web",
					Port:       PrometheusDefaultPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(prometheusServiceListenPort),
				},
			},
		},
	}

	return s
}

// deployment for the Prometheus Service/Proxy pod and image
func (p *tigeraPrometheusAPIComponent) deployment(prometheusServiceListenPort int) *appsv1.Deployment {
	var replicas int32 = 1
	podDnsPolicy := corev1.DNSClusterFirst
	podHostNetworked := false

	// set to host networked if cluster is on EKS using Calico CNI since the EKS managed Kubernetes APIserver
	// cannot reach the pod network in this configuration. This is because Calico cannot manage
	// the managed control plane nodes' network
	if p.installation.KubernetesProvider == operatorv1.ProviderEKS &&
		p.installation.CNI.Type == operatorv1.PluginCalico {
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
			Name:      TigeraPrometheusAPIName,
			Namespace: common.TigeraPrometheusNamespace,
			Labels: map[string]string{
				"k8s-app": TigeraPrometheusAPIName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": TigeraPrometheusAPIName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      TigeraPrometheusAPIName,
					Namespace: common.TigeraPrometheusNamespace,
					Labels: map[string]string{
						"k8s-app": TigeraPrometheusAPIName,
					},
				},
				Spec: corev1.PodSpec{
					DNSPolicy:        podDnsPolicy,
					HostNetwork:      podHostNetworked,
					ImagePullSecrets: secret.GetReferenceList(p.pullSecrets),
					NodeSelector:     p.installation.ControlPlaneNodeSelector,
					Tolerations:      append(p.installation.ControlPlaneTolerations, rmeta.TolerateMaster),
					Containers: []corev1.Container{
						p.tigeraPrometheusAPIContainers(prometheusServiceListenPort),
					},
				},
			},
		},
	}

	return d
}

//
func (p *tigeraPrometheusAPIComponent) tigeraPrometheusAPIContainers(prometheusServiceListenPort int) corev1.Container {
	prometheusOperatedHttpUrl := url.URL{
		Scheme: prometheusOperatedHttpServiceScheme,
		Host:   prometheusOperatedHttpServiceHost + ":" + strconv.Itoa(PrometheusDefaultPort),
	}

	prometheusServiceListenAddrValue := ":" + strconv.Itoa(prometheusServiceListenPort)

	c := corev1.Container{
		Name:            TigeraPrometheusAPIName,
		Image:           p.prometheusServiceImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: int32(prometheusServiceListenPort),
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
					Port: intstr.FromInt(prometheusServiceListenPort),
				},
			},
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: tigeraPrometheusServiceHealthEndpoint,
					Port: intstr.FromInt(prometheusServiceListenPort),
				},
			},
		},
	}

	return c
}

// getDefaultConfigMap returns a ConfigMap object containing default values for
// instantiating tigera-prometheus-api component
func (p *tigeraPrometheusAPIComponent) getDefaultConfigMap() *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraPrometheusAPIName,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string]string{
			tigeraPrometheusAPIListenPortFieldName: strconv.Itoa(PrometheusDefaultPort),
		},
	}

	return cm
}
