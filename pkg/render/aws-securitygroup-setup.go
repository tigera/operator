// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"github.com/tigera/operator/pkg/components"

	operator "github.com/tigera/operator/api/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func AWSSecurityGroupSetup(ps []corev1.LocalObjectReference, installcr *operator.InstallationSpec) (Component, error) {
	return &awsSGSetupComponent{pullSecrets: ps, installcr: installcr}, nil
}

type awsSGSetupComponent struct {
	pullSecrets []corev1.LocalObjectReference
	installcr   *operator.InstallationSpec
}

func (c *awsSGSetupComponent) SupportedOSType() OSType {
	return OSTypeLinux
}

func (c *awsSGSetupComponent) Objects() ([]runtime.Object, []runtime.Object) {
	return []runtime.Object{
		c.serviceAccount(),
		c.role(),
		c.roleBinding(),
		c.setupJob(),
	}, nil
}

func (c *awsSGSetupComponent) Ready() bool {
	return true
}

func (c *awsSGSetupComponent) setupJob() *batchv1.Job {
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-security-group-setup-1",
			Namespace: OperatorNamespace(),
		},
		Spec: batchv1.JobSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"job-name": "aws-security-group-setup-1",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"job-name": "aws-security-group-setup-1"},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyOnFailure,
					ImagePullSecrets:   c.pullSecrets,
					ServiceAccountName: TigeraAWSSGSetupName,
					HostNetwork:        true,
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
						{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
						{Operator: corev1.TolerationOpExists, Key: "CriticalAddonsOnly"},
					},
					Containers: []corev1.Container{{
						Name:  "aws-security-group-setup",
						Image: components.GetOperatorInitReference(c.installcr.Registry, c.installcr.ImagePath),
						Args:  []string{"--aws-sg-setup"},
						Env: []corev1.EnvVar{
							{
								Name:  "OPENSHIFT",
								Value: "true",
							},
							{
								Name:  "REQUIRE_AWS",
								Value: "true",
							},
							{
								Name:  "KUBELET_KUBECONFIG",
								Value: "/etc/kubernetes/kubeconfig",
							},
						},
						SecurityContext: securityContext(),
					}},
				},
			},
		},
	}
}

const TigeraAWSSGSetupName = "tigera-aws-security-group-setup"

func (c *awsSGSetupComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraAWSSGSetupName,
			Namespace: OperatorNamespace(),
		},
	}
}

// roleBinding creates a clusterrolebinding giving the node service account the required permissions to operate.
func (c *awsSGSetupComponent) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraAWSSGSetupName,
			Namespace: metav1.NamespaceSystem,
			Labels:    map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     TigeraAWSSGSetupName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      TigeraAWSSGSetupName,
				Namespace: OperatorNamespace(),
			},
		},
	}
}

// nodeRole creates the clusterrole containing policy rules that allow the node daemonset to operate normally.
func (c *awsSGSetupComponent) role() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraAWSSGSetupName,
			Namespace: metav1.NamespaceSystem,
			Labels:    map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{"aws-creds"},
				Verbs:         []string{"get"},
			},
		},
	}
}
