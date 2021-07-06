package render

import (
	operator "github.com/tigera/operator/api/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	prometheusPort                    = 9090
	prometheusOperatedHttpServiceName = "prometheus-operated-http"
	calicoNodePrometheusServiceName   = "calico-node-prometheus"

	tigeraPrometheusServiceName = "tigera-prometheus-service"
)

func PrometheusService(cr *operator.InstallationSpec, pullSecrets []*corev1.Secret) Component {

	return &prometheusServiceComponent{
		pullSecrets: pullSecrets,
	}
}

type prometheusServiceComponent struct {
	installation           *operatorv1.InstallationSpec
	pullSecrets            []*corev1.Secret
	prometheusServiceImage string
}

func (p *prometheusServiceComponent) ResolveImages(is *operator.ImageSet) error {
	reg := p.installation.Registry
	path := p.installation.ImagePath
	prefix := p.installation.ImagePrefix

	prometheusServiceImage, err := components.GetReference(components.ComponentPrometheusAlertmanager, reg, path, prefix, is)
	if err != nil {
		return err
	}

	p.prometheusServiceImage = prometheusServiceImage

	return nil
}

// Objects returns the lists of objects in this component that should be created and/or deleted during
// rendering.
func (p *prometheusServiceComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	// tigera-prometheus-objects
	namespacedObjects := []client.Object{}

	// place pullsecrets secrets under tigera-prometheus
	secrets := secret.CopyToNamespace(rmeta.APIServerNamespace(p.installation.Variant), p.pullSecrets...)
	namespacedObjects = append(namespacedObjects, secret.ToRuntimeObjects(secrets...)...)

	isEksWithCalicoCNI := p.installation.KubernetesProvider == operatorv1.ProviderEKS &&
		p.installation.CNI.Type == operatorv1.PluginCalico

	namespacedObjects = append(
		namespacedObjects,
		p.calicoNodePrometheusService(isEksWithCalicoCNI),
	)

	if isEksWithCalicoCNI {
		namespacedObjects = append(
			namespacedObjects,
			p.prometheusServiceDeployment(),
			p.prometheusOperatedHttpService(),
		)
	}

	objsToCreate = []client.Object{}
	objsToCreate = append(objsToCreate, namespacedObjects...)

	objsToDelete = []client.Object{}

	return objsToCreate, objsToDelete

}

// Ready returns true if the component is ready to be created.
func (p *prometheusServiceComponent) Ready() bool {
	return false
}

// SupportedOSTypes returns operating systems that is supported of the components returned by the Objects() function.
// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on client.Objects
// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
func (p *prometheusServiceComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

// calicoNodePrometheusService sets up a service for the Prometheus Service/Proxy deployment
func (p *prometheusServiceComponent) calicoNodePrometheusService(isEksWithCalicoCNI bool) *corev1.Service {
	prometheusDeploymentSelector := map[string]string{
		"k8s-app": tigeraPrometheusServiceName,
	}

	if isEksWithCalicoCNI {
		prometheusDeploymentSelector = map[string]string{
			"prometheus": calicoNodePrometheusServiceName,
		}
	}

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
			Ports: []corev1.ServicePort{
				{
					Name:       "web",
					Port:       prometheusPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(prometheusPort),
				},
			},
			Selector: prometheusDeploymentSelector,
		},
	}

	return s
}

// TODO: reconsider this to move to render/monitor
// prometheusOperatedHttpService sets up a service to open http connection for a prometheus instance
func (p *prometheusServiceComponent) prometheusOperatedHttpService() *corev1.Service {
	s := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      prometheusOperatedHttpServiceName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "web",
					Port:       prometheusPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(prometheusPort),
				},
			},
			Selector: map[string]string{
				"prometheus": calicoNodePrometheusServiceName,
			},
		},
	}

	return s
}

func (p *prometheusServiceComponent) prometheusServiceDeployment() *appsv1.Deployment {
	var replicas int32 = 1
	podDnsPolicy := corev1.DNSClusterFirstWithHostNet
	podHostNetworked := true

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      tigeraPrometheusServiceName,
			Namespace: common.TigeraPrometheusNamespace,
			Labels: map[string]string{
				"k8s-app": tigeraPrometheusServiceName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": tigeraPrometheusServiceName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tigeraPrometheusServiceName,
					Namespace: common.TigeraPrometheusNamespace,
					Labels: map[string]string{
						"k8s-app": tigeraPrometheusServiceName,
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

func (p *prometheusServiceComponent) prometheusServiceContainers() corev1.Container {
	prometheusEndpointUrlEnvVarName := "PROMETHEUS_ENDPOINT_URL"
	prometheusOperatedHttpServiceUrl := "http://prometheus-operated-http.tigera-prometheus:9090"
	prometheusServiceHealthEndpoint := "/health"

	c := corev1.Container{
		Name:            tigeraPrometheusServiceName,
		Image:           p.prometheusServiceImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: prometheusPort,
			},
		},
		Env: []corev1.EnvVar{
			{
				Name:  prometheusEndpointUrlEnvVarName,
				Value: prometheusOperatedHttpServiceUrl,
			},
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: prometheusServiceHealthEndpoint,
					Port: intstr.FromInt(prometheusPort),
				},
			},
			InitialDelaySeconds: 10,
			PeriodSeconds:       5,
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: prometheusServiceHealthEndpoint,
					Port: intstr.FromInt(prometheusPort),
				},
			},
			InitialDelaySeconds: 10,
			PeriodSeconds:       5,
		},
	}

	return c
}
