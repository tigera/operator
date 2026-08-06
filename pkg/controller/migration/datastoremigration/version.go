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

package datastoremigration

import (
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
)

var log = ctrl.Log.WithName("datastoremigration")

// ResolveServedVersion points the package at the version the cluster serves. Call it before
// AddToScheme: scheme, cache and watches must agree.
func ResolveServedVersion(disco discovery.DiscoveryInterface) {
	gv, ok := ServedGroupVersion(disco)
	if !ok {
		// The CRD is installed by the user when they migrate, so it's usually absent at startup.
		log.V(1).Info("No DatastoreMigration CRD served, defaulting", "groupVersion", SchemeGroupVersion)
		return
	}
	log.Info("Resolved served DatastoreMigration version", "groupVersion", gv)
	SchemeGroupVersion = gv
}

// ServedGroupVersion returns the DatastoreMigration group/version the cluster serves, preferring v1.
// The second return is false when the CRD isn't installed.
func ServedGroupVersion(disco discovery.DiscoveryInterface) (schema.GroupVersion, bool) {
	for _, gv := range []schema.GroupVersion{GroupVersionV1, GroupVersionV1beta1} {
		resources, err := disco.ServerResourcesForGroupVersion(gv.String())
		if err != nil {
			if !apierrors.IsNotFound(err) {
				log.Error(err, "Failed to look up served DatastoreMigration versions", "groupVersion", gv)
			}
			continue
		}
		for _, r := range resources.APIResources {
			if r.Name == Resource {
				return gv, true
			}
		}
	}
	return schema.GroupVersion{}, false
}

// WatchObject returns an empty DatastoreMigration stamped with the resolved group/version, for
// controllers registering a watch.
func WatchObject() *DatastoreMigration {
	return &DatastoreMigration{
		TypeMeta: metav1.TypeMeta{Kind: Kind, APIVersion: SchemeGroupVersion.String()},
	}
}
