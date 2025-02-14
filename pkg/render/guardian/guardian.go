package guardian

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	_k8s "github.com/tigera/operator/pkg/k8s"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	GuardianContainerName              = "guardian"
	GuardianVolumeName                 = "tigera-guardian-certs"
	GuardianServiceName                = "tigera-guardian"
	ManagedClusterConnectionSecretName = "tigera-managed-cluster-connection"
)

func Container(tunnelCAType operatorv1.CAType, voltronURL string,
	bundle certificatemanagement.TrustedBundle, tunnelSecret *corev1.Secret, proxyEnvVars []corev1.EnvVar) *_k8s.Container {

	return _k8s.NewContainer(GuardianContainerName, components.Component{
		Image:    "calico/guardian",
		Version:  "bmv1.4",
		Registry: "gcr.io/unique-caldron-775/brianmcmahon/",
	}).
		AddEnv(
			[]corev1.EnvVar{
				{Name: "GUARDIAN_PORT", Value: "9443"},
				{Name: "GUARDIAN_LOGLEVEL", Value: "DEBUG"},
				{Name: "GUARDIAN_VOLTRON_URL", Value: voltronURL},
				{Name: "GUARDIAN_VOLTRON_CA_TYPE", Value: string(tunnelCAType)},
				{Name: "GUARDIAN_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: bundle.MountPath()},
				{Name: "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH", Value: bundle.MountPath()},
				{Name: "GUARDIAN_QUERYSERVER_CA_BUNDLE_PATH", Value: bundle.MountPath()},
			}...).AddEnv(proxyEnvVars...).
		MountConfigMap(bundle.VolumeMountPath(rmeta.OSTypeLinux), bundle.ConfigMap("")).
		MountSecret("/certs", copySecret(tunnelSecret)).
		AddService(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: GuardianServiceName,
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{
						Name: "linseed",
						Port: 443,
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 8080,
						},
						Protocol: corev1.ProtocolTCP,
					},
					{
						Name: "elasticsearch",
						Port: 9200,
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 8080,
						},
						Protocol: corev1.ProtocolTCP,
					},
					{
						Name: "kibana",
						Port: 5601,
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 8080,
						},
						Protocol: corev1.ProtocolTCP,
					},
				},
			},
		})
}

func copySecret(s *corev1.Secret) *corev1.Secret {
	x := s.DeepCopy()
	x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: s.Namespace}

	return x

}
