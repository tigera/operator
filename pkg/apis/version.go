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

package apis

import (
	"context"
	"errors"
	"os"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/tigera/operator/pkg/controller/migration/datastoremigration"
)

var datastoreMigrationGVR = schema.GroupVersionResource{
	Group:    "migration.projectcalico.org",
	Version:  "v1beta1",
	Resource: "datastoremigrations",
}

const (
	mutatingAdmissionPolicyGroup = "admissionregistration.k8s.io"
	mutatingAdmissionPolicyKind  = "MutatingAdmissionPolicy"
)

var log = ctrl.Log.WithName("apis")

// errV3RequiresMAP is returned when we've concluded v3 CRD mode but the cluster can't serve
// MutatingAdmissionPolicy. v3 mode relies on a MAP to default policy types, so we refuse to
// operate rather than run in a degraded state where defaulting silently doesn't happen.
var errV3RequiresMAP = errors.New("v3 CRD mode requires MutatingAdmissionPolicy support (Kubernetes 1.32+), which this cluster does not serve")

// UseV3CRDS detects whether we should use the crd.projectcalico.org/v1 or
// projectcalico.org/v3 API group for Calico CRDs.
func UseV3CRDS(cfg *rest.Config) (bool, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, err
	}
	disco := cs.Discovery()

	if apiGroup := os.Getenv("CALICO_API_GROUP"); apiGroup != "" {
		log.Info("CALICO_API_GROUP environment variable is set, using its value to determine API group", "CALICO_API_GROUP", apiGroup)
		return requireMAPForV3(apiGroup == "projectcalico.org/v3", disco)
	}

	// Check if a DatastoreMigration CR exists in a state that indicates v3 CRDs
	// should be used. This handles operator restarts during or after migration.
	// This runs before the manager cache is started, so we use a dynamic client
	// directly rather than the cached datastoremigration.GetPhase().
	if migrated, err := checkDatastoreMigration(cfg); err != nil {
		log.Info("Failed to check DatastoreMigration CR, falling through to API discovery", "error", err)
	} else if migrated {
		return requireMAPForV3(true, disco)
	}

	return useV3CRDsFromDiscovery(disco)
}

// requireMAPForV3 gates a v3 decision on MutatingAdmissionPolicy support. When v3 is chosen but
// the cluster can't serve MAP we return an error and refuse to operate; a v1 decision passes
// through untouched (and skips the discovery call). Used by the paths that assert v3 without
// cluster CRD evidence - the CALICO_API_GROUP override and a converged DatastoreMigration.
func requireMAPForV3(useV3 bool, disco discovery.DiscoveryInterface) (bool, error) {
	if useV3 && !mutatingAdmissionPolicyServed(disco) {
		return false, errV3RequiresMAP
	}
	return useV3, nil
}

// useV3CRDsFromDiscovery is the discovery-success path of UseV3CRDS, split out so it can be tested
// with a fake discovery client.
func useV3CRDsFromDiscovery(disco discovery.DiscoveryInterface) (bool, error) {
	apiGroups, err := disco.ServerGroups()
	if err != nil {
		return false, err
	}

	v3present, v1present := false, false
	for _, g := range apiGroups.Groups {
		if g.Name == v3.GroupName {
			v3present = true
		}
		if g.Name == "crd.projectcalico.org" {
			v1present = true
		}
	}

	// v1 present always wins (existing/upgraded install), so only pay for the MutatingAdmissionPolicy
	// discovery call when v3 is still in play - an existing v3 install we must gate, or a greenfield
	// default we can only take when MAP is servable.
	mapServed := false
	if !v1present {
		mapServed = mutatingAdmissionPolicyServed(disco)
	}

	log.Info("Detected API groups from API server", "v3present", v3present, "v1present", v1present, "mapServed", mapServed)
	return decideV3CRDs(v1present, v3present, mapServed)
}

// checkDatastoreMigration uses a dynamic client to look for a DatastoreMigration CR
// and returns true if one exists in a phase that indicates v3 CRDs should be used.
// This is used at startup before the manager cache is available.
func checkDatastoreMigration(cfg *rest.Config) (bool, error) {
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return false, err
	}
	list, err := dc.Resource(datastoreMigrationGVR).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, item := range list.Items {
		status, ok := item.Object["status"].(map[string]any)
		if !ok {
			continue
		}
		phase, _ := status["phase"].(string)
		if phase == datastoremigration.PhaseConverged || phase == datastoremigration.PhaseComplete {
			log.Info("DatastoreMigration CR found in post-migration phase, using v3 CRDs", "name", item.GetName(), "phase", phase)
			return true, nil
		}
	}
	return false, nil
}

// decideV3CRDs returns whether the operator should use the projectcalico.org/v3 API group,
// given which Calico CRD groups are present in the cluster and whether the cluster serves
// MutatingAdmissionPolicy. This covers the discovery-success path only; the CALICO_API_GROUP
// override and the DatastoreMigration check are handled by the caller.
//
//   - If the v1 CRDs are present, the cluster is an existing/upgraded install (or has opted out
//     by pre-installing v1 CRDs), so use v1.
//   - If only the v3 CRDs are present, the cluster is already on v3; never downgrade it, but v3
//     mode needs MutatingAdmissionPolicy, so error out if the cluster can't serve it.
//   - If neither is present, this is a brand-new install. Default to v3, but only if the cluster
//     can serve MutatingAdmissionPolicy (needed to default policy types in v3 mode); otherwise
//     fall back to v1.
func decideV3CRDs(v1present, v3present, mapServed bool) (bool, error) {
	if v1present {
		return false, nil
	}
	if v3present {
		if !mapServed {
			return false, errV3RequiresMAP
		}
		return true, nil
	}
	return mapServed, nil
}

// mutatingAdmissionPolicyServed reports whether the cluster serves the MutatingAdmissionPolicy
// API (any version). v3 CRD mode relies on a MutatingAdmissionPolicy to default policy types, so
// a greenfield install only defaults to v3 when this is available (k8s 1.32+).
//
// This is best-effort: ServerGroupsAndResources can return a partial result with an error when an
// aggregated API is unhealthy, so we log and continue with whatever was returned rather than
// failing. MutatingAdmissionPolicy is served by the core kube-apiserver, so an unhealthy
// aggregated API server doesn't affect whether we find it.
func mutatingAdmissionPolicyServed(disco discovery.DiscoveryInterface) bool {
	_, resourceLists, err := disco.ServerGroupsAndResources()
	if err != nil {
		log.Info("Partial error discovering server resources while checking for MutatingAdmissionPolicy; continuing with partial results", "error", err)
	}
	for _, rl := range resourceLists {
		gv, parseErr := schema.ParseGroupVersion(rl.GroupVersion)
		if parseErr != nil || gv.Group != mutatingAdmissionPolicyGroup {
			continue
		}
		for _, r := range rl.APIResources {
			if r.Kind == mutatingAdmissionPolicyKind {
				return true
			}
		}
	}
	return false
}
