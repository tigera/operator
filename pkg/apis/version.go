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
	"os"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

var log = ctrl.Log.WithName("apis")

// UseV3CRDS detects whether we should use the crd.projectcalic.org/v1 or
// projectcalico.org/v3 API group for Calico CRDs.
func UseV3CRDS(cs kubernetes.Interface) (bool, error) {
	if os.Getenv("CALICO_API_GROUP") != "" {
		log.Info("CALICO_API_GROUP environment variable is set, using its value to determine API group", "CALICO_API_GROUP", os.Getenv("CALICO_API_GROUP"))
		return os.Getenv("CALICO_API_GROUP") == "projectcalico.org/v3", nil
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
