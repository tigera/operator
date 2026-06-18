// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package enterprise

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
)

func registerTypha(s *extensions.Set) {
	s.Register(operatorv1.CalicoEnterprise, render.ComponentNameTypha, extensions.ComponentExtension{
		Modify: modifyTypha,
	})
}

func modifyTypha(ctx extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
	if role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "calico-typha"); ok {
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"bfdconfigurations",
				"deeppacketinspections",
				"egressgatewaypolicies",
				"externalnetworks",
				"licensekeys",
				"networks",
				"packetcaptures",
				"remoteclusterconfigurations",
			},
			Verbs: []string{"get", "list", "watch"},
		})
	}

	if dep, ok := extensions.FindObject[*appsv1.Deployment](objs, "calico-typha"); ok {
		net := ctx.Installation.CalicoNetwork
		if net != nil && net.MultiInterfaceMode != nil {
			for i := range dep.Spec.Template.Spec.Containers {
				if dep.Spec.Template.Spec.Containers[i].Name == render.TyphaContainerName {
					c := &dep.Spec.Template.Spec.Containers[i]
					c.Env = append(c.Env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: net.MultiInterfaceMode.Value()})
				}
			}
		}
	}

	return objs, del
}
