// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package render

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

const (
	CNICalico = "calico"
	CNINone   = "none"
)

type NetworkConfig struct {
	CNI                  string
	NodenameFileOptional bool
	IPPools              []operatorv1.IPPool
}

type BPFConfig struct {
	BPFEnabled bool
	BPFDSR     bool
	K8sHost    string
	K8sPort    int
}

func GenerateBPFConfig(install *operatorv1.Installation) (BPFConfig, error) {
	var cfg BPFConfig

	if install.Spec.BPFDataplaneMode != nil {
		switch *install.Spec.BPFDataplaneMode {
		case operatorv1.BPFEnabledDSR:
			cfg.BPFDSR = true
			fallthrough
		case operatorv1.BPFEnabled:
			cfg.BPFEnabled = true
		}
	}

	return cfg, nil
}
