// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	AmazonCloudIntegrationNamespace      = "tigera-amazon-cloud-integration"
	AmazonCloudIntegrationComponentName  = "tigera-amazon-cloud-integration"
	AmazonCloudIntegrationCredentialName = "amazon-cloud-integration-credentials"
	AmazonCloudCredentialKeyIdName       = "key-id"
	AmazonCloudCredentialKeySecretName   = "key-secret"
	credentialSecretHashAnnotation       = "hash.operator.tigera.io/credential-secret"
)

func AmazonCloudIntegration(cfg *AmazonCloudIntegrationConfiguration) Component {
	return &amazonCloudIntegrationComponent{cfg: cfg}
}

// AmazonCloudIntegrationConfiguration contains all the config information needed to render the component.
type AmazonCloudIntegrationConfiguration struct {
	AmazonCloudIntegration *operatorv1.AmazonCloudIntegration
	Installation           *operatorv1.InstallationSpec
	Credentials            *AmazonCredential
	PullSecrets            []*corev1.Secret
	TrustedBundle          certificatemanagement.TrustedBundle
}

type amazonCloudIntegrationComponent struct {
	cfg   *AmazonCloudIntegrationConfiguration
	image string
}

func (c *amazonCloudIntegrationComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.image, err = components.GetReference(components.ComponentCloudControllers, reg, path, prefix, is)
	return err
}

func (c *amazonCloudIntegrationComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

type AmazonCredential struct {
	KeyId     []byte
	KeySecret []byte
}

func ConvertSecretToCredential(s *corev1.Secret) (*AmazonCredential, error) {
	if s == nil {
		return nil, fmt.Errorf("no secret specified")
	}

	missingKey := []string{}
	var ok bool
	var kId []byte
	if kId, ok = s.Data[AmazonCloudCredentialKeyIdName]; !ok || len(kId) == 0 {
		missingKey = append(missingKey, AmazonCloudCredentialKeyIdName)
	}

	var kSecret []byte
	if kSecret, ok = s.Data[AmazonCloudCredentialKeySecretName]; !ok || len(kSecret) == 0 {
		missingKey = append(missingKey, AmazonCloudCredentialKeySecretName)
	}

	if len(missingKey) > 0 {
		return nil, fmt.Errorf("%s secret needs %s",
			AmazonCloudIntegrationCredentialName,
			strings.Join(missingKey, " and "))
	}

	return &AmazonCredential{KeyId: kId, KeySecret: kSecret}, nil
}

func (c *amazonCloudIntegrationComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		CreateNamespace(AmazonCloudIntegrationNamespace, c.cfg.Installation.KubernetesProvider, PSSRestricted),
	}
	secrets := secret.CopyToNamespace(AmazonCloudIntegrationNamespace, c.cfg.PullSecrets...)
	objs = append(objs, secret.ToRuntimeObjects(secrets...)...)
	objs = append(objs,
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.credentialSecret(),
		c.cfg.TrustedBundle.ConfigMap(AmazonCloudIntegrationNamespace),
		c.deployment(),
	)

	return objs, nil
}

func (c *amazonCloudIntegrationComponent) Ready() bool {
	return true
}

// serviceAccount creates the service account used by the API server.
func (c *amazonCloudIntegrationComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      AmazonCloudIntegrationComponentName,
			Namespace: AmazonCloudIntegrationNamespace,
		},
	}
}

// clusterRole creates a clusterrole that gives permissions to access backing CRDs and
// k8s networkpolicies.
func (c *amazonCloudIntegrationComponent) clusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: AmazonCloudIntegrationComponentName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"*"},
				Resources: []string{
					"nodes",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"globalnetworkpolicies",
					"networkpolicies",
					"tiers",
					"clusterinformations",
					"hostendpoints",
					"licensekeys",
				},
				Verbs: []string{
					"create",
					"get",
					"list",
					"update",
					"watch",
					"delete",
				},
			},
		},
	}
}

// clusterRoleBinding creates a clusterrolebinding that applies apiServiceAccountClusterRole to
// the tigera-apiserver service account.
func (c *amazonCloudIntegrationComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: AmazonCloudIntegrationComponentName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      AmazonCloudIntegrationComponentName,
				Namespace: AmazonCloudIntegrationNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     AmazonCloudIntegrationComponentName,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func (c *amazonCloudIntegrationComponent) credentialSecret() *corev1.Secret {
	if c.cfg.Credentials == nil {
		return nil
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      AmazonCloudIntegrationCredentialName,
			Namespace: AmazonCloudIntegrationNamespace,
		},
		Data: map[string][]byte{
			AmazonCloudCredentialKeyIdName:     c.cfg.Credentials.KeyId,
			AmazonCloudCredentialKeySecretName: c.cfg.Credentials.KeySecret,
		},
	}
}

// deployment creates a deployment containing the API and query servers.
func (c *amazonCloudIntegrationComponent) deployment() *appsv1.Deployment {
	var replicas int32 = 1

	annotations := make(map[string]string)
	annotations[credentialSecretHashAnnotation] = rmeta.AnnotationHash(c.cfg.Credentials)
	for k, v := range c.cfg.TrustedBundle.HashAnnotations() {
		annotations[k] = v
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      AmazonCloudIntegrationComponentName,
			Namespace: AmazonCloudIntegrationNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        AmazonCloudIntegrationComponentName,
					Namespace:   AmazonCloudIntegrationNamespace,
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: AmazonCloudIntegrationComponentName,
					Tolerations:        rmeta.TolerateAll,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers: []corev1.Container{
						c.container(),
					},
					Volumes: []corev1.Volume{
						c.cfg.TrustedBundle.Volume(),
					},
				},
			},
		},
	}
	SetClusterCriticalPod(&d.Spec.Template)

	return d
}

// container creates the API server container.
func (c *amazonCloudIntegrationComponent) container() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "FAILSAFE_CONTROLLER_APP_NAME", Value: AmazonCloudIntegrationComponentName},
		{Name: "CLOUDWATCH_HEALTHREPORTING_ENABLED", Value: "false"},
		{Name: "VPCS", Value: strings.Join(c.cfg.AmazonCloudIntegration.Spec.VPCS, ",")},
		{Name: "SQS_URL", Value: c.cfg.AmazonCloudIntegration.Spec.SQSURL},
		{Name: "AWS_REGION", Value: c.cfg.AmazonCloudIntegration.Spec.AWSRegion},
		{Name: "TIGERA_ENFORCED_GROUP_ID", Value: c.cfg.AmazonCloudIntegration.Spec.EnforcedSecurityGroupID},
		{Name: "TIGERA_TRUST_ENFORCED_GROUP_ID", Value: c.cfg.AmazonCloudIntegration.Spec.TrustEnforcedSecurityGroupID},
		{Name: "AWS_SECRET_ACCESS_KEY", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: AmazonCloudIntegrationCredentialName,
				},
				Key: AmazonCloudCredentialKeySecretName,
			},
		}},
		{Name: "AWS_ACCESS_KEY_ID", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: AmazonCloudIntegrationCredentialName,
				},
				Key: AmazonCloudCredentialKeyIdName,
			},
		}},
	}

	if c.cfg.AmazonCloudIntegration.Spec.DefaultPodMetadataAccess == operatorv1.MetadataAccessAllowed {
		env = append(env, corev1.EnvVar{Name: "ALLOW_POD_METADATA_ACCESS", Value: "true"})
	}

	return corev1.Container{
		Name:            AmazonCloudIntegrationComponentName,
		Image:           c.image,
		ImagePullPolicy: ImagePullPolicy(),
		Env:             env,
		SecurityContext: securitycontext.NewNonRootContext(),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"check-status",
						"-r",
					},
				},
			},
			InitialDelaySeconds: 10,
		},
		VolumeMounts: c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()),
	}
}

func GetTigeraSecurityGroupEnvVariables(aci *operatorv1.AmazonCloudIntegration) []corev1.EnvVar {
	envs := []corev1.EnvVar{}
	if aci == nil {
		return envs
	}

	nodeSGIDs := aci.Spec.NodeSecurityGroupIDs
	if len(nodeSGIDs) > 0 {
		envs = append(envs, corev1.EnvVar{
			Name:  "TIGERA_DEFAULT_SECURITY_GROUPS",
			Value: strings.Join(nodeSGIDs, ","),
		})
	}
	podSGID := aci.Spec.PodSecurityGroupID
	if podSGID != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "TIGERA_POD_SECURITY_GROUP",
			Value: podSGID,
		})
	}

	return envs
}
