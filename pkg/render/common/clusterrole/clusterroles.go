// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package clusterrole

import (
	v1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ToRuntimeObjects converts the given list of cluster roles to a list of client.Objects
func ToRuntimeObjects(clusterRoles ...*v1.ClusterRole) []client.Object {
	var objs []client.Object
	for _, clusterRole := range clusterRoles {
		if clusterRole == nil {
			continue
		}
		objs = append(objs, clusterRole)
	}
	return objs
}
