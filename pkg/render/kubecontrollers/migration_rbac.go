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

package kubecontrollers

import (
	"context"
	"fmt"

	logrus "github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
)

const (
	MigrationClusterRoleName        = "calico-kube-controllers-migration"
	migrationClusterRoleBindingName = "calico-kube-controllers-migration"
)

var datastoreMigrationGVR = schema.GroupVersionResource{
	Group:    "migration.projectcalico.org",
	Version:  "v1beta1",
	Resource: "datastoremigrations",
}

// migrationRBACObjects returns the ClusterRole and ClusterRoleBinding that grant
// calico-kube-controllers broad access to both API groups during a datastore migration.
func migrationRBACObjects() []client.Object {
	return []client.Object{
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: MigrationClusterRoleName},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
					Resources: []string{"*"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{"apiregistration.k8s.io"},
					Resources: []string{"apiservices"},
					Verbs:     []string{"get", "list", "watch", "create", "delete"},
				},
				{
					APIGroups: []string{"apiextensions.k8s.io"},
					Resources: []string{"customresourcedefinitions"},
					Verbs:     []string{"get", "list", "delete"},
				},
			},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: migrationClusterRoleBindingName},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     MigrationClusterRoleName,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "calico-kube-controllers",
					Namespace: common.CalicoNamespace,
				},
			},
		},
	}
}

// MigrationRBACComponent returns a render component that creates or deletes the
// migration RBAC depending on whether a DatastoreMigration CR exists. When a
// migration is active, kube-controllers needs broad access to both API groups
// to read v1 resources and write v3 resources. When no migration exists, the
// extra permissions are cleaned up.
func MigrationRBACComponent(cfg *rest.Config) (render.Component, error) {
	if cfg == nil {
		logrus.Info("MigrationRBACComponent: no config, returning deletion passthrough")
		return render.NewDeletionPassthrough(migrationRBACObjects()...), nil
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client for migration check: %w", err)
	}
	list, err := dc.Resource(datastoreMigrationGVR).List(context.Background(), metav1.ListOptions{Limit: 1})
	if err != nil {
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			logrus.Info("MigrationRBACComponent: DatastoreMigration CRD not found, returning deletion passthrough")
			return render.NewDeletionPassthrough(migrationRBACObjects()...), nil
		}
		return nil, fmt.Errorf("listing DatastoreMigration CRs: %w", err)
	}
	if len(list.Items) > 0 {
		logrus.WithField("count", len(list.Items)).Info("MigrationRBACComponent: DatastoreMigration CR found, creating migration RBAC")
		return render.NewCreationPassthrough(migrationRBACObjects()...), nil
	}
	logrus.Info("MigrationRBACComponent: no DatastoreMigration CRs found, returning deletion passthrough")
	return render.NewDeletionPassthrough(migrationRBACObjects()...), nil
}
