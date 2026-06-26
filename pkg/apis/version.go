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

// UseV3CRDS detects whether we should use the crd.projectcalico.org/v1 or
// projectcalico.org/v3 API group for Calico CRDs.
func UseV3CRDS(cfg *rest.Config) (bool, error) {
	if os.Getenv("CALICO_API_GROUP") != "" {
		log.Info("CALICO_API_GROUP environment variable is set, using its value to determine API group", "CALICO_API_GROUP", os.Getenv("CALICO_API_GROUP"))
		return os.Getenv("CALICO_API_GROUP") == "projectcalico.org/v3", nil
	}

	// Check if a DatastoreMigration CR exists in a state that indicates v3 CRDs
	// should be used. This handles operator restarts during or after migration.
	// This runs before the manager cache is started, so we use a dynamic client
	// directly rather than the cached datastoremigration.GetPhase().
	if v3, err := checkDatastoreMigration(cfg); err != nil {
		log.Info("Failed to check DatastoreMigration CR, falling through to API discovery", "error", err)
	} else if v3 {
		return true, nil
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, err
	}
	apiGroups, err := cs.Discovery().ServerGroups()
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

	log.Info("Detected API groups from API server", "v3present", v3present, "v1present", v1present)
	return v3present && !v1present, nil
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
//   - If only the v3 CRDs are present, the cluster is already on v3; never downgrade it.
//   - If neither is present, this is a brand-new install. Default to v3, but only if the cluster
//     can serve MutatingAdmissionPolicy (needed to default policy types in v3 mode).
func decideV3CRDs(v1present, v3present, mapServed bool) bool {
	if v1present {
		return false
	}
	if v3present {
		return true
	}
	return mapServed
}

// mutatingAdmissionPolicyServed reports whether the cluster serves the MutatingAdmissionPolicy
// API (any version). v3 CRD mode relies on a MutatingAdmissionPolicy to default policy types, so
// a greenfield install only defaults to v3 when this is available (k8s 1.32+).
//
// This is best-effort: ServerGroupsAndResources can return a partial result with an error when an
// aggregated API is unhealthy, so we log and continue with whatever was returned rather than
// failing. It is only called in the greenfield branch, where no aggregated APIs exist yet.
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
