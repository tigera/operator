// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package render

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/render/common/configmap"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
)

// IntrusionDetectionCloudResources contains all the resource needed for cloud intrusion detection controller.
type IntrusionDetectionCloudResources struct {
	ImageAssuranceResources *rcimageassurance.Resources
}

func (c *intrusionDetectionComponent) decorateIntrusionDetectionContainer(container corev1.Container) corev1.Container {
	// if image assurance is enabled add env needed for it.
	if c.cfg.CloudResources.ImageAssuranceResources != nil {
		container.Env = append(container.Env,
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_CA_BUNDLE_PATH", Value: rcimageassurance.CABundlePath},
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_ENDPOINT", Value: rcimageassurance.APIEndpoint},
			corev1.EnvVar{
				Name: "IMAGE_ASSURANCE_ORGANIZATION_ID",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: rcimageassurance.ConfigurationConfigMapName},
						Key:                  rcimageassurance.ConfigurationConfigMapOrgIDKey,
					},
				}},
			corev1.EnvVar{
				Name: "IMAGE_ASSURANCE_API_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "image-assurance-api-token"},
						Key:                  "token",
					},
				}},
		)
		container.VolumeMounts = append(container.VolumeMounts,
			corev1.VolumeMount{
				MountPath: rcimageassurance.CAMountPath,
				Name:      rcimageassurance.ImageAssuranceSecretName,
				ReadOnly:  true,
			},
		)
	}
	return container
}

func (c *intrusionDetectionComponent) decorateIntrusionDetectionCloudDeploymentSpec(templateSpec corev1.PodTemplateSpec) corev1.PodTemplateSpec {
	// if image assurance is enabled add env needed for it.
	if c.cfg.CloudResources.ImageAssuranceResources != nil {
		templateSpec.ObjectMeta.Annotations[rcimageassurance.ImageAssuranceCertHashAnnotation] = rmeta.AnnotationHash(c.cfg.CloudResources.ImageAssuranceResources.TLSSecret.Data)
		templateSpec.Spec.Volumes = append(templateSpec.Spec.Volumes,
			corev1.Volume{
				Name: rcimageassurance.ImageAssuranceSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						Items: []corev1.KeyToPath{{
							Key:  "tls.crt",
							Path: "tls.crt",
						}},
						SecretName: rcimageassurance.ImageAssuranceSecretName,
					},
				},
			})
	}
	return templateSpec
}

func (c *intrusionDetectionComponent) addCloudResources(objs []client.Object) []client.Object {
	// if image assurance is enabled add corresponding resources.
	if c.cfg.CloudResources.ImageAssuranceResources != nil {
		objs = append(objs, secret.ToRuntimeObjects(&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: rcimageassurance.ImageAssuranceSecretName, Namespace: IntrusionDetectionNamespace},
			Data: map[string][]byte{
				corev1.TLSCertKey: c.cfg.CloudResources.ImageAssuranceResources.TLSSecret.Data[corev1.TLSCertKey],
			},
		})...)

		objs = append(objs, configmap.ToRuntimeObjects(configmap.CopyToNamespace(IntrusionDetectionNamespace, c.cfg.CloudResources.ImageAssuranceResources.ConfigurationConfigMap)...)...)
		objs = append(objs, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "image-assurance-api-token",
				Namespace: IntrusionDetectionNamespace,
			},
			Data: map[string][]byte{
				"token": c.cfg.CloudResources.ImageAssuranceResources.ImageAssuranceToken,
			},
		})
	}

	return objs
}

func (c *intrusionDetectionComponent) imageAssuranceAPIClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: IntrusionDetectionControllerImageAssuranceAPIClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{
				"imageassurance.tigera.io",
			},
			Resources: []string{
				"organizations",
			},
			Verbs: []string{
				"get",
			},
			ResourceNames: []string{
				c.cfg.CloudResources.ImageAssuranceResources.ConfigurationConfigMap.Data[rcimageassurance.ConfigurationConfigMapOrgIDKey],
			},
		}},
	}
}
