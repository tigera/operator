package whisker

//func (c *Component) whisker() *_k8s.Container {
//	return _k8s.NewContainer("whisker", components.Component{
//		Image:    "calico/whisker",
//		Version:  "bmv1.10",
//		Registry: "gcr.io/unique-caldron-775/brianmcmahon/",
//	}).AddEnv(
//		[]corev1.EnvVar{
//			{Name: "LOG_LEVEL", Value: "DEBUG"},
//			{Name: "CA_CERT_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
//		}...).MountConfigMap(c.cfg.TrustedCertBundle.VolumeMountPath(rmeta.OSTypeLinux), c.cfg.TrustedCertBundle.ConfigMap("")).
//		AddService(&corev1.Service{
//			ObjectMeta: metav1.ObjectMeta{Name: "whisker"},
//			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8081}}},
//		})
//}
//
//func (c *Component) whiskerBackend() *_k8s.Container {
//	return _k8s.NewContainer("whisker-backend", components.Component{
//		Image:    "calico/whisker-backend",
//		Version:  "bmv1.10",
//		Registry: "gcr.io/unique-caldron-775/brianmcmahon/",
//	}).AddEnv([]corev1.EnvVar{
//		{Name: "LOG_LEVEL", Value: "DEBUG"},
//		{Name: "CA_CERT_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
//		{Name: "PORT", Value: "3002"},
//		{Name: "GOLDMANE_HOST", Value: "localhost:7443"},
//	}...).
//		MountConfigMap(c.cfg.TrustedCertBundle.VolumeMountPath(rmeta.OSTypeLinux), c.cfg.TrustedCertBundle.ConfigMap(""))
//}
//
//func (c *Component) goldmane() *_k8s.Container {
//	ctr := _k8s.NewContainer("goldmane", components.Component{
//		Image:    "calico/goldmane",
//		Version:  "bmv1.10",
//		Registry: "gcr.io/unique-caldron-775/brianmcmahon/",
//	}).
//		AddEnv(
//			[]corev1.EnvVar{
//				{Name: "LOG_LEVEL", Value: "INFO"},
//				{Name: "CA_CERT_PATH", Value: "/certs/tls.crt"},
//				{Name: "PORT", Value: "7443"},
//			}...,
//		).
//		AddService(&corev1.Service{
//			ObjectMeta: metav1.ObjectMeta{
//				Name: "goldmane",
//			},
//			Spec: corev1.ServiceSpec{
//				Ports: []corev1.ServicePort{{Port: 7443}},
//			},
//		})
//	if c.cfg.LinseedPublicCASecret != nil {
//		ctr.
//			MountSecret("/certs", copySecret(c.cfg.LinseedPublicCASecret)).
//			AddEnv([]corev1.EnvVar{
//				{Name: "PUSH_URL", Value: fmt.Sprintf("https://%s.%s.svc/api/v1/flows/bulk", "tigera-guardian", WhiskerNamespace)},
//			}...)
//	}
//
//	return ctr
//}
//
//func (c *Component) guardian() *_k8s.Container {
//	tunnelCAType := c.cfg.ManagementClusterConnection.Spec.TLS.CA
//	voltronURL := c.cfg.ManagementClusterConnection.Spec.ManagementClusterAddr
//	bundle := c.cfg.TrustedCertBundle
//	tunnelSecret := c.cfg.TunnelSecret
//	proxyEnvVars := c.cfg.Installation.Proxy.EnvVars()
//
//	return _k8s.NewContainer(GuardianContainerName, components.Component{
//		Image:    "calico/guardian",
//		Version:  "bmv1.10",
//		Registry: "gcr.io/unique-caldron-775/brianmcmahon/",
//	}).
//		AddEnv(
//			[]corev1.EnvVar{
//				{Name: "GUARDIAN_PORT", Value: "9443"},
//				{Name: "GUARDIAN_LOGLEVEL", Value: "DEBUG"},
//				{Name: "GUARDIAN_VOLTRON_URL", Value: voltronURL},
//				{Name: "GUARDIAN_VOLTRON_CA_TYPE", Value: string(tunnelCAType)},
//				{Name: "GUARDIAN_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: bundle.MountPath()},
//				{Name: "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH", Value: bundle.MountPath()},
//				{Name: "GUARDIAN_QUERYSERVER_CA_BUNDLE_PATH", Value: bundle.MountPath()},
//			}...).AddEnv(proxyEnvVars...).
//		MountConfigMap(bundle.VolumeMountPath(rmeta.OSTypeLinux), bundle.ConfigMap("")).
//		MountSecret("/certs", copySecret(tunnelSecret)).
//		AddService(&corev1.Service{
//			ObjectMeta: metav1.ObjectMeta{
//				Name: GuardianServiceName,
//			},
//			Spec: corev1.ServiceSpec{
//				Ports: []corev1.ServicePort{
//					{
//						Name: "linseed",
//						Port: 443,
//						TargetPort: intstr.IntOrString{
//							Type:   intstr.Int,
//							IntVal: 8080,
//						},
//						Protocol: corev1.ProtocolTCP,
//					},
//					{
//						Name: "elasticsearch",
//						Port: 9200,
//						TargetPort: intstr.IntOrString{
//							Type:   intstr.Int,
//							IntVal: 8080,
//						},
//						Protocol: corev1.ProtocolTCP,
//					},
//					{
//						Name: "kibana",
//						Port: 5601,
//						TargetPort: intstr.IntOrString{
//							Type:   intstr.Int,
//							IntVal: 8080,
//						},
//						Protocol: corev1.ProtocolTCP,
//					},
//				},
//			},
//		})
//}
