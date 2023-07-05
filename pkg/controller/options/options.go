// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package options

import (
	"context"

	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
)

// AddOptions are passed to controllers when added to the controller manager. They
// detail options detected by the daemon at startup that some controllers may either
// use to determine if they should run at all, or store them and influence their
// reconciliation loops.
type AddOptions struct {
	DetectedProvider    v1.Provider
	EnterpriseCRDExists bool
	AmazonCRDExists     bool
	ClusterDomain       string
	KubernetesVersion   *common.VersionInfo
	ManageCRDs          bool
	ShutdownContext     context.Context

	// Whether or not the operator is running in multi-tenant mode.
	// When true, this means some CRDs are installed as namespace scoped
	// instead of cluster scoped.
	MultiTenant bool

	// Whether or not the cluster supports PodSecurityPolicies.
	UsePSP bool
}
