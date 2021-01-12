// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
)

const (
	CSRClusterRoleName   = "tigera-csr-creator"
	CSRInitContainerName = "key-cert-provisioner"
)

// CreateCSRInitContainer creates an init container that can be added to a pod spec in order to create a CSR for its
// TLS certificates. It uses the provided params and the k8s downward api to be able to specify certificate subject information.
func CreateCSRInitContainer(
	installation *operator.InstallationSpec,
	image string,
	mountName string,
	commonName string,
	keyName string,
	certName string,
	dnsNames []string,
	appNameLabel string) corev1.Container {
	return corev1.Container{
		Name:  CSRInitContainerName,
		Image: image,
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/certs-share", Name: mountName, ReadOnly: false},
		},
		Env: []corev1.EnvVar{
			{Name: "CERTIFICATE_PATH", Value: "/certs-share/"},
			{Name: "SIGNER", Value: installation.CertificateManagement.SignerName},
			{Name: "COMMON_NAME", Value: commonName},
			{Name: "KEY_ALGORITHM", Value: fmt.Sprintf("%v", installation.CertificateManagement.KeyAlgorithm)},
			{Name: "SIGNATURE_ALGORITHM", Value: fmt.Sprintf("%v", installation.CertificateManagement.SignatureAlgorithm)},
			{Name: "KEY_NAME", Value: keyName},
			{Name: "CERT_NAME", Value: certName},
			{Name: "APP_NAME", Value: appNameLabel},
			{Name: "DNS_NAMES", Value: strings.Join(dnsNames, ",")},
			{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "status.podIP",
				},
			}},
			{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			}},
			{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			}},
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged:               Bool(false),
			AllowPrivilegeEscalation: Bool(false),
		},
	}
}

// ResolveCsrInitImage resolves the image needed for the CSR init image taking into account the specified ImageSet
func ResolveCSRInitImage(inst *operator.InstallationSpec, is *operator.ImageSet) (string, error) {
	return components.GetReference(
		components.ComponentCSRInitContainer,
		inst.Registry,
		inst.ImagePath,
		is,
	)
}

// csrClusterRole returns a role with the necessary permissions to create certificate signing requests.
func csrClusterRole() client.Object {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   CSRClusterRoleName,
			Labels: map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests"},
				Verbs:     []string{"create", "watch", "delete"},
			},
		},
	}
}

// csrClusterRoleBinding returns a role binding with the necessary permissions to create certificate signing requests.
func csrClusterRoleBinding(name, namespace string) *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("%s:csr-creator", name),
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     CSRClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      name,
				Namespace: namespace,
			},
		},
	}
	return crb
}

func certificateVolumeSource(certificateManagement *operator.CertificateManagement, secretName string) corev1.VolumeSource {
	if certificateManagement != nil {
		return corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		}
	} else {
		return corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: secretName,
			},
		}
	}
}
