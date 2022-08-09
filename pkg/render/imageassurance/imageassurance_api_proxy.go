// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	"github.com/tigera/operator/pkg/ptr"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	APIProxyResourceName = "tigera-image-assurance-api-proxy"

	apiProxyRequestCPU    = "0.25"
	apiProxyRequestMemory = "50Mi"
	apiProxyLimitCPU      = "0.75"
	apiProxyLimitMemory   = "150Mi"
)

func (c *component) apiProxyDeployment() *appsv1.Deployment {
	env := []corev1.EnvVar{
		rcimageassurance.EnvOrganizationID(),
		{Name: "IMAGE_ASSURANCE_PORT", Value: "5557"},
		{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_HTTPS_CERT", Value: "/certs/https/tls.crt"},
		{Name: "IMAGE_ASSURANCE_HTTPS_KEY", Value: "/certs/https/tls.key"},
		{Name: "IMAGE_ASSURANCE_PROXY_URL", Value: "https://ia-api.dev.calicocloud.io"},
		{Name: "IMAGE_ASSURANCE_PROXY_HTTPS_CERT", Value: "/certs/https/tls.crt"},
		{Name: "AUTH0_AUDIENCE", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "audience",
			},
		}},
		{Name: "AUTH0_CLIENT_ID", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "client_id",
			},
		}},
		{Name: "AUTH0_CLIENT_SECRET", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "client_secret",
			},
		}},
		{Name: "AUTH0_TOKEN_URL", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "token_url",
			},
		}},
		{Name: "AUTH0_CLOUD_BASE_URL", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "cloud_base_url",
			},
		}},
	}

	terminationGracePeriod := int64(30)

	volumeMounts := []corev1.VolumeMount{
		{Name: APICertSecretName, MountPath: mountPathAPITLSCerts, ReadOnly: true},
		c.config.TrustedCertBundle.VolumeMount(),
	}

	if c.config.KeyValidatorConfig != nil {
		env = append(env, c.config.KeyValidatorConfig.RequiredEnv("IMAGE_ASSURANCE_")...)
		volumeMounts = append(volumeMounts, c.config.KeyValidatorConfig.RequiredVolumeMounts()...)
	}

	container := corev1.Container{
		Name:            "tigera-image-assurance-api-proxy",
		Image:           c.config.apiProxyImage,
		ImagePullPolicy: corev1.PullAlways,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(apiProxyRequestCPU),
				corev1.ResourceMemory: resource.MustParse(apiProxyRequestMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(apiProxyLimitCPU),
				corev1.ResourceMemory: resource.MustParse(apiProxyLimitMemory),
			},
		},
		Env:          env,
		VolumeMounts: volumeMounts,
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIProxyResourceName,
			Namespace: NameSpaceImageAssurance,
			Labels: map[string]string{
				"k8s-app": APIProxyResourceName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": APIProxyResourceName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIProxyResourceName,
					Namespace: NameSpaceImageAssurance,
					Labels: map[string]string{
						"k8s-app": APIProxyResourceName,
					},
				},
				Spec: corev1.PodSpec{
					DNSPolicy:                     corev1.DNSClusterFirst,
					ImagePullSecrets:              c.config.Installation.ImagePullSecrets,
					NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
					RestartPolicy:                 corev1.RestartPolicyAlways,
					ServiceAccountName:            ResourceNameImageAssuranceAPI,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					Containers:                    []corev1.Container{container},
					Volumes:                       c.apiProxyVolumes(),
				},
			},
		},
	}
}

func (c *component) apiProxyVolumes() []corev1.Volume {
	defaultMode := int32(420)

	volumes := []corev1.Volume{
		{
			Name: APICertSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  APICertSecretName,
					DefaultMode: &defaultMode,
				},
			},
		},
		c.config.TrustedCertBundle.Volume(),
	}

	if c.config.KeyValidatorConfig != nil {
		volumes = append(volumes, c.config.KeyValidatorConfig.RequiredVolumes()...)
	}

	return volumes
}
