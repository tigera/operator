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
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
)

var log = ctrl.Log.WithName("apis")

// DatastoreMigrationGVR is the GroupVersionResource for DatastoreMigration CRs.
var DatastoreMigrationGVR = schema.GroupVersionResource{
	Group:    "migration.projectcalico.org",
	Version:  "v1beta1",
	Resource: "datastoremigrations",
}

// UseV3CRDS detects whether we should use the crd.projectcalico.org/v1 or
// projectcalico.org/v3 API group for Calico CRDs.
func UseV3CRDS(cfg *rest.Config) (bool, error) {
	if os.Getenv("CALICO_API_GROUP") != "" {
		log.Info("CALICO_API_GROUP environment variable is set, using its value to determine API group", "CALICO_API_GROUP", os.Getenv("CALICO_API_GROUP"))
		return os.Getenv("CALICO_API_GROUP") == "projectcalico.org/v3", nil
	}

	// Check if a DatastoreMigration CR exists in a state that indicates v3 CRDs
	// should be used. This handles operator restarts during or after migration.
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
func checkDatastoreMigration(cfg *rest.Config) (bool, error) {
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return false, err
	}
	list, err := dc.Resource(DatastoreMigrationGVR).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, item := range list.Items {
		status, ok := item.Object["status"].(map[string]any)
		if !ok {
			continue
		}
		phase, _ := status["phase"].(string)
		if phase == "Converged" || phase == "Complete" {
			log.Info("DatastoreMigration CR found in post-migration phase, using v3 CRDs", "name", item.GetName(), "phase", phase)
			return true, nil
		}
	}
	return false, nil
}
