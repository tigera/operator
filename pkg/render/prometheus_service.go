package render

import (
	"net/url"
	"strconv"

	operator "github.com/tigera/operator/api/v1"
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
	calicoNodePrometheusServiceName = "calico-node-prometheus"

	tigeraPrometheusServiceName           = "tigera-prometheus-service"
	prometheusEndpointUrlEnvVarName       = "PROMETHEUS_ENDPOINT_URL"
	prometheusOperatedHttpServiceScheme   = "http"
	prometheusOperatedHttpServiceHost     = "prometheus-operated-http.tigera-prometheus"
	tigeraPrometheusServiceHealthEndpoint = "/health"
)

func TigeraPrometheusService(cr *operator.InstallationSpec, pullSecrets []*corev1.Secret, prometheusServicePort int) Component {

	if prometheusServicePort < 0 {
		prometheusServicePort = PrometheusDefaultPort
	}

	return &tigeraPrometheusServiceComponent{
		installation:          cr,
		pullSecrets:           pullSecrets,
		prometheusServicePort: prometheusServicePort,
	}
}

type tigeraPrometheusServiceComponent struct {
	installation           *operator.InstallationSpec
	pullSecrets            []*corev1.Secret
	prometheusServicePort  int
	prometheusServiceImage string
}

func (p *tigeraPrometheusServiceComponent) ResolveImages(is *operator.ImageSet) error {
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
func (p *tigeraPrometheusServiceComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	// tigera-prometheus-objects
	namespacedObjects := []client.Object{}

	// place pullsecrets secrets under tigera-prometheus
	secrets := secret.CopyToNamespace(rmeta.APIServerNamespace(p.installation.Variant), p.pullSecrets...)
	namespacedObjects = append(namespacedObjects, secret.ToRuntimeObjects(secrets...)...)

	namespacedObjects = append(
		namespacedObjects,
		p.calicoNodePrometheusService(),
		p.tigeraPrometheusServiceDeployment(),
	)

	objsToCreate = []client.Object{}
	objsToCreate = append(objsToCreate, namespacedObjects...)

	objsToDelete = []client.Object{}

	return objsToCreate, objsToDelete

}

func (p *tigeraPrometheusServiceComponent) Ready() bool {
	return true
}

func (p *tigeraPrometheusServiceComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

// calicoNodePrometheusService sets up a service for the Prometheus Service/Proxy deployment
func (p *tigeraPrometheusServiceComponent) calicoNodePrometheusService() *corev1.Service {

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
					Port:       PrometheusDefaultPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(p.prometheusServicePort),
				},
			},
			Selector: map[string]string{
				"k8s-app": tigeraPrometheusServiceName,
			},
		},
	}

	return s
}

// tigeraPrometheusServiceDeployment deployment for the Prometheus Service/Proxy pod and image
func (p *tigeraPrometheusServiceComponent) tigeraPrometheusServiceDeployment() *appsv1.Deployment {
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

func (p *tigeraPrometheusServiceComponent) prometheusServiceContainers() corev1.Container {
	prometheusOperatedHttpUrl := url.URL{
		Scheme: prometheusOperatedHttpServiceScheme,
		Host:   prometheusOperatedHttpServiceHost + ":" + strconv.Itoa(p.prometheusServicePort),
	}

	c := corev1.Container{
		Name:            tigeraPrometheusServiceName,
		Image:           p.prometheusServiceImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: PrometheusDefaultPort,
			},
		},
		Env: []corev1.EnvVar{
			{
				Name:  prometheusEndpointUrlEnvVarName,
				Value: prometheusOperatedHttpUrl.String(),
			},
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: tigeraPrometheusServiceHealthEndpoint,
					Port: intstr.FromInt(PrometheusDefaultPort),
				},
			},
			InitialDelaySeconds: 10,
			PeriodSeconds:       5,
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: tigeraPrometheusServiceHealthEndpoint,
					Port: intstr.FromInt(PrometheusDefaultPort),
				},
			},
			InitialDelaySeconds: 10,
			PeriodSeconds:       5,
		},
	}

	return c
}
