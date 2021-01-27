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

package common

import (
	operator "github.com/tigera/operator/api/v1"
)

const (
	CalicoNamespace     = "calico-system"
	TyphaDeploymentName = "calico-typha"
	NodeDaemonSetName   = "calico-node"

	TigeraPrometheusNamespace = "tigera-prometheus"
)

type Installation struct {
	Spec                *operator.InstallationSpec
	TigeraCustom        bool
	NodeAppArmorProfile string
}
