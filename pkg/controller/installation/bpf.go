// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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

package installation

import (
	"errors"
	"reflect"
	"strconv"

	"github.com/tigera/operator/pkg/controller/utils"

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// updateBPFEnabledAllowed validate Felix Configuration annotations match BPF Enabled spec for all scenarios.
func updateBPFEnabledAllowed(fc *crdv1.FelixConfiguration) error {
	var annotationValue *bool
	if fc.Annotations[render.BPFOperatorAnnotation] != "" {
		v, err := strconv.ParseBool(fc.Annotations[render.BPFOperatorAnnotation])
		annotationValue = &v
		if err != nil {
			return err
		}
	}

	// The values are considered matching if one of the following is true:
	// - Both values are nil
	// - Neither are nil and they have the same value.
	// Otherwise, the we consider the annotation to not match the spec field.
	match := annotationValue == nil && fc.Spec.BPFEnabled == nil
	match = match || annotationValue != nil && fc.Spec.BPFEnabled != nil && *annotationValue == *fc.Spec.BPFEnabled

	if !match {
		return errors.New(`Unable to set bpfEnabled: FelixConfiguration "default" has been modified by someone else, refusing to override potential user configuration.`)
	}

	return nil
}

// If the Installation resource has been patched to dataplane: BPF then the
// calico-node daemonset will be re-created with BPF infrastructure such as
// the "bpffs" volumne mount etc. which will cause the DS to do a rolling update.
// Therefore, one way to check that the daemonset rolling update is complete is
// to compare the DS status current scheduled pods equals the updated number and
// the current scheduled pods also equals the number available.  When all these
// checks are reconciled then FelixConfig can be patched as bpfEnabled: true.
func isRolloutComplete(ds *appsv1.DaemonSet) bool {
	for _, volume := range ds.Spec.Template.Spec.Volumes {
		if volume.Name == render.BPFVolumeName {
			return ds.Status.CurrentNumberScheduled == ds.Status.UpdatedNumberScheduled && ds.Status.CurrentNumberScheduled == ds.Status.NumberAvailable
		}
	}

	return false
}

func setBPFEnabled(fc *crdv1.FelixConfiguration, bpfEnabled bool) error {
	err := updateBPFEnabledAllowed(fc)
	if err != nil {
		return err
	}

	text := strconv.FormatBool(bpfEnabled)

	// Add an annotation matching the field value. This allows the operator to compare the annotation to the field
	// when performing an update to determine if another entity has modified the value since the last write.
	var fcAnnotations map[string]string
	if fc.Annotations == nil {
		fcAnnotations = make(map[string]string)
	} else {
		fcAnnotations = fc.Annotations
	}
	fcAnnotations[render.BPFOperatorAnnotation] = text
	fc.SetAnnotations(fcAnnotations)
	fc.Spec.BPFEnabled = &bpfEnabled

	return nil
}

func bpfEnabledOnDaemonSet(ds *appsv1.DaemonSet) (bool, error) {
	bpfEnabledStatus := false
	var err error

	if ds != nil &&
		!reflect.DeepEqual(ds.Spec, appsv1.DaemonSetSpec{}) &&
		!reflect.DeepEqual(ds.Spec.Template, corev1.PodTemplateSpec{}) &&
		!reflect.DeepEqual(ds.Spec.Template.Spec, corev1.PodSpec{}) {
		bpfEnabledEnvVar := utils.GetPodEnvVar(ds.Spec.Template.Spec, common.NodeDaemonSetName, "FELIX_BPFENABLED")
		if bpfEnabledEnvVar != nil {
			bpfEnabledStatus, err = strconv.ParseBool(*bpfEnabledEnvVar)
		}
	}

	return bpfEnabledStatus, err
}

func bpfEnabledOnFelixConfig(fc *crdv1.FelixConfiguration) bool {
	return fc.Spec.BPFEnabled != nil && *fc.Spec.BPFEnabled
}
