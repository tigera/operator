// Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.

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
	"k8s.io/client-go/kubernetes"
)

// AddOptions are passed to controllers when added to the controller manager. They
// detail options detected by the daemon at startup that some controllers may either
// use to determine if they should run at all, or store them and influence their
// reconciliation loops.
type AddOptions struct {
	DetectedProvider    v1.Provider
	EnterpriseCRDExists bool
	ClusterDomain       string
	KubernetesVersion   *common.VersionInfo
	ManageCRDs          bool
	ShutdownContext     context.Context

	// Nameservers contains the nameservers configured for the operator. Most pods do not need explicit
	// nameservers specified, as they will use the default nameservers configured in the cluster. However, any pods
	// that must function prior to cluster DNS being available (e.g., the operator itself and calico/node)
	// may need to have the nameservers explicitly set if configured to access the Kubernetes API via a domain name.
	Nameservers []string

	// Kubernetes clientset used by controllers to create watchers and informers.
	K8sClientset *kubernetes.Clientset

	// Whether or not the operator is running in multi-tenant mode.
	// When true, this means some CRDs are installed as namespace scoped
	// instead of cluster scoped.
	MultiTenant bool

	// Whether or not the operator is running in a management cluster configured to
	// use external elasticsearch. When set, the operator will not install Elasticsearch
	// and instead will configure the cluster to use an external Elasticsearch.
	ElasticExternal bool
}
