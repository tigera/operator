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
	operator "github.com/tigera/operator/pkg/apis/operator/v1"

	v3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	apps "k8s.io/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func Compliance(cr *operator.Installation) Component {
	return &component{
		objs: []runtime.Object{
			complianceControllerServiceAccount(cr),
			complianceControllerClusterRole(cr),
			complianceControllerRoleBinding(cr),
			complianceControllerClusterRoleBinding(cr),
			complianceControllerDeployment(cr),

			complianceReporterServiceAccount(cr),
			complianceReporterClusterRole(cr),
			complianceReporterClusterRoleBinding(cr),
			complianceReporterDaemonSet(cr),

			complianceServerServiceAccount(cr),
			complianceServerClusterRole(cr),
			complianceServerClusterRoleBinding(cr),
			complianceServerService(cr),
			complianceServerDeployment(cr),

			complianceSnapshotterServiceAccount(cr),
			complianceSnapshotterClusterRole(cr),
			complianceSnapshotterClusterRoleBinding(cr),
			complianceSnapshotterDeployment(cr),

			complianceGlobalReportInventory(cr),
			complianceGlobalReportNetworkAccess(cr),
			complianceGlobalReportPolicyAudit(cr),
		},
		deps: []runtime.Object{},
	}
}

// compliance-controller
func complianceControllerServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{}
}

func complianceControllerClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{}
}

func complianceControllerRoleBinding(cr *operator.Installation) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{}
}

func complianceControllerClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{}
}

func complianceControllerDeployment(cr *operator.Installation) *appsv1.Deployment {
	return &appsv1.Deployment{}
}

// compliance-reporter
func complianceReporterServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{}
}

func complianceReporterClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{}
}

func complianceReporterClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{}
}

func complianceReporterDaemonSet(cr *operator.Installation) *apps.DaemonSet {
	return &apps.DaemonSet{}
}

// compliance-server
func complianceServerServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{}
}

func complianceServerClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{}
}

func complianceServerClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{}
}

func complianceServerService(cr *operator.Installation) *v1.Service {
	return &v1.Service{}
}

func complianceServerDeployment(cr *operator.Installation) *appsv1.Deployment {
	return &appsv1.Deployment{}
}

// compliance-snapshotter
func complianceSnapshotterServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{}
}

func complianceSnapshotterClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{}
}

func complianceSnapshotterClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{}
}

func complianceSnapshotterDeployment(cr *operator.Installation) *appsv1.Deployment {
	return &appsv1.Deployment{}
}

// compliance-report-types
func complianceGlobalReportInventory(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{}
}
func complianceGlobalReportNetworkAccess(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{}
}
func complianceGlobalReportPolicyAudit(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{}
}
