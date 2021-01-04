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

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func CreateCSRInitContainer(
	installation *operator.InstallationSpec,
	cm *operator.CertificateManagement,
	mountName string,
	commonName string,
	keyName string,
	certName string,
	dnsNames []string,
	registerApiserver bool) corev1.Container {
	return corev1.Container{
		Name:            "key-cert-provisioner",
		Image:           components.GetReference(components.ComponentCSRInitContainer, "docker.io/", installation.ImagePath), //todo: Set the right registry.
		ImagePullPolicy: "Always",                                                                                            //todo: delete this line.
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/secret", Name: mountName, ReadOnly: false},
		},
		Env: []corev1.EnvVar{
			{Name: "SECRET_LOCATION", Value: "/secret/"},
			{Name: "SIGNER", Value: cm.SignerName},
			{Name: "COMMON_NAME", Value: commonName},
			{Name: "KEY_ALGORITHM", Value: fmt.Sprintf("%v", installation.CertificateManagement.KeyAlgorithm)},
			{Name: "SIGNATURE_ALGORITHM", Value: fmt.Sprintf("%v", installation.CertificateManagement.SignatureAlgorithm)},
			{Name: "REGISTER_APISERVER", Value: fmt.Sprintf("%v", registerApiserver)},
			{Name: "KEY_NAME", Value: keyName},
			{Name: "CERT_NAME", Value: certName},
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
			{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.uid",
				},
			}},
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged:               Bool(false),
			AllowPrivilegeEscalation: Bool(false),
		},
	}
}

// A role with the necessary permissions to create certificate signing requests.
func csrClusterRole() runtime.Object {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "tigera-csr-creator",
			Labels: map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests"},
				Verbs:     []string{"create", "watch"},
			},
		},
	}
}

// A role binding with the necessary permissions to create certificate signing requests.
func csrClusterRoleBinding(name, namespace string) *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("%s-%s:csr-creator", namespace, name),
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-csr-creator",
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
