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

package convert

import "fmt"

// ErrIncompatibleCluster indicates that a config option was detected in the existing install
// which Operator does not support.
type ErrIncompatibleCluster struct {
	// err describes the error
	err string
	// fix explains what the user can do, if anything, to continue the migration.
	fix string
	// component identifies which component caused the problem.
	component string
}

func (e ErrIncompatibleCluster) Error() string {
	if e.fix != "" {
		return fmt.Sprintf("%s. To fix it, %s on %s", e.err, e.fix, e.component)
	}
	return fmt.Sprintf("%s on %s", e.err, e.component)
}

const (
	ComponentCalicoNode      = "daemonset/calico-node"
	ComponentKubeControllers = "deployment/calico-kube-controllers"
	ComponentTypha           = "deployment/calico-typha"
	ComponentCNIConfig       = "cni-config"
	ComponentIPPools         = "ippools"
)

func ErrMissingHostPathVolume(component, volume, hostPath string) ErrIncompatibleCluster {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("did not detect expected '%s' volume with hostPath '%s'", volume, hostPath),
		component: component,
		fix:       fmt.Sprintf("add the expected volume to %s", component),
	}
}

func ErrIncompatibleAnnotation(annotKey, component string) error {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("annotation %q differs in the Installation and the migration source", annotKey),
		component: component,
		fix:       "remove the annotation from the Installation resource, or remove it from the component",
	}
}

func ErrAnnotationsOnlyOnInstall(component string) error {
	return ErrIncompatibleCluster{
		err:       "annotations were found in the Installation but not the migration source",
		component: component,
		fix:       "remove the annotations from the Installation resource, or add them to the component",
	}
}

func ErrIncompatibleLabel(labelKey, component string) error {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("label %q differs in the Installation and the migration source", labelKey),
		component: component,
		fix:       "remove the label from the Installation resource, or remove it from the component",
	}
}

func ErrLabelsOnlyOnInstall(component string) error {
	return ErrIncompatibleCluster{
		err:       "labels were found in the Installation but not the migration source",
		component: component,
		fix:       "remove the labels from the Installation resource, or add them to the component",
	}
}

func ErrIncompatibleNodeSelector(nodeSelectorKey, component string) error {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("nodeSelector %q differs in the Installation and the migration source", nodeSelectorKey),
		component: component,
		fix:       "remove the nodeSelector from the Installation resource, or remove it from the component",
	}
}

func ErrNodeSelectorOnlyOnInstall(component string) error {
	return ErrIncompatibleCluster{
		err:       "nodeSelector found in the Installation did not match the migration source",
		component: component,
		fix:       "remove the nodeSelector from the Installation resource, or add it to the component",
	}
}

func ErrIncompatibleAffinity(component string) error {
	return ErrIncompatibleCluster{
		err:       "affinity differs in the Installation and the migration source",
		component: component,
		fix:       "remove the affinity from the Installation resource, or remove it from the component",
	}
}

func ErrIncompatibleMinReadySeconds(component string) error {
	return ErrIncompatibleCluster{
		err:       "minReadySeconds differs in the Installation and the migration source",
		component: component,
		fix:       "remove the minReadySeconds from the Installation resource, or remove it from the component",
	}
}

func ErrIncompatibleTolerations(component string) error {
	return ErrIncompatibleCluster{
		err:       "tolerations differ in the Installation and the migration source",
		component: component,
		fix:       "remove the tolerations from the Installation resource, or remove them from the component",
	}
}
