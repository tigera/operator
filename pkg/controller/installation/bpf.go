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
	"context"
	"errors"
	"fmt"
	"strconv"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/controller/utils"

	"github.com/go-logr/logr"
	operator "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
)

func bpfUpgradeWithoutDisruption(r *ReconcileInstallation, ctx context.Context, install *operator.Installation, ds *appsv1.DaemonSet, fc *crdv1.FelixConfiguration, reqLogger logr.Logger) error {
	var patchFelixConfig bool

	// Check the install dataplane mode is either Iptables or BPF.
	installBpfEnabled := common.BPFDataplaneEnabled(&install.Spec)

	// Check edge case where User has externally patched FelixConfig bpfEnabled which causes conflict to prevent Operator from upgrading dataplane.
	if fc.Spec.BPFEnabled != nil {

		fcBPFEnabled := *fc.Spec.BPFEnabled
		if installBpfEnabled != fcBPFEnabled {

			// Ensure Felix Config annotations are either empty or equal previous FC bpfEnabled value.
			if fc.Annotations[render.BpfOperatorAnnotation] == strconv.FormatBool(installBpfEnabled) {
				err := errors.New("Unable to set bpfEnabled: FelixConfiguration \"default\" has been modified by someone else, refusing to override potential user configuration.")
				return err
			}
		}
	}

	if !installBpfEnabled {
		// IP Tables dataplane:
		// Only patch Felix Config once to prevent log spamming.
		if fc.Spec.BPFEnabled == nil || *fc.Spec.BPFEnabled {
			patchFelixConfig = true
		}
	} else {
		// BPF dataplane:
		// Check daemonset rollout complete before patching.
		if fc.Spec.BPFEnabled == nil || !(*fc.Spec.BPFEnabled) {
			patchFelixConfig = checkDaemonsetRolloutComplete(ds)
		}
	}

	// Attempt to patch Felix Config now.
	return patchFelixConfigurationImpl(r, ctx, install, fc, reqLogger, patchFelixConfig)
}

// If the Installation resource has been patched to dataplane: BPF then the
// calico-node daemonset will be re-created with BPF infrastructure such as
// the "bpffs" volumne mount etc. which will cause the DS to do a rolling update.
// Therefore, one way to check that the daemonset rolling update is complete is
// to compare the DS status current scheduled pods equals the updated number and
// the current scheduled pods also equals the number available.  When all these
// checks are reconciled then FelixConfig can be patched as bpfEnabled: true.
func checkDaemonsetRolloutComplete(ds *appsv1.DaemonSet) bool {
	for _, volume := range ds.Spec.Template.Spec.Volumes {
		if volume.Name == common.BPFVolumeName {
			return ds.Status.CurrentNumberScheduled == ds.Status.UpdatedNumberScheduled && ds.Status.CurrentNumberScheduled == ds.Status.NumberAvailable
		}
	}

	return false
}

func patchFelixConfigurationImpl(r *ReconcileInstallation, ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, reqLogger logr.Logger, patchFelixConfig bool) error {
	if patchFelixConfig {
		installBpfEnabled := common.BPFDataplaneEnabled(&install.Spec)
		err := patchFelixConfiguration(r, ctx, fc, reqLogger, installBpfEnabled)
		if err != nil {
			return err
		}

		// Ensure if no errors occurred while attempting to patch Falix Config then successfully patched.
		patchFelixConfig = err == nil
	}

	if patchFelixConfig {
		if fc.Spec.BPFEnabled != nil {
			msg := fmt.Sprintf("Successfully patched Felix Config OK bpfEnabled='%s'", strconv.FormatBool(*fc.Spec.BPFEnabled))
			reqLogger.Info(msg)
		}
	}

	return nil
}

func patchFelixConfiguration(r *ReconcileInstallation, ctx context.Context, fc *crdv1.FelixConfiguration, reqLogger logr.Logger, patchBpfEnabled bool) error {
	// Obtain the original FelixConfig to patch.
	patchFrom := client.MergeFrom(fc.DeepCopy())
	patchText := strconv.FormatBool(patchBpfEnabled)

	// Add managed fields "light".
	var fcAnnotations map[string]string
	if fc.Annotations == nil {
		fcAnnotations = make(map[string]string)
	} else {
		fcAnnotations = fc.Annotations
	}
	fcAnnotations[render.BpfOperatorAnnotation] = patchText
	fc.SetAnnotations(fcAnnotations)

	fc.Spec.BPFEnabled = &patchBpfEnabled
	if err := r.client.Patch(ctx, fc, patchFrom); err != nil {
		msg := fmt.Sprintf("An error occurred when attempting to patch Felix configuration BPF Enabled: '%s'", patchText)
		reqLogger.Error(err, msg)
		return err
	}

	return nil
}

// TODO - reanme
func stevepro(fc *crdv1.FelixConfiguration, bpfEnabled bool) {
	text := strconv.FormatBool(bpfEnabled)

	// Add managed fields "light".
	var fcAnnotations map[string]string
	if fc.Annotations == nil {
		fcAnnotations = make(map[string]string)
	} else {
		fcAnnotations = fc.Annotations
	}
	fcAnnotations[render.BpfOperatorAnnotation] = text
	fc.SetAnnotations(fcAnnotations)

	fc.Spec.BPFEnabled = &bpfEnabled
}

func bpfEnabledOnDaemonSet(ds *appsv1.DaemonSet) bool {
	dsBpfEnabledStatus := false
	dsBpfEnabledEnvVar := utils.GetPodEnvVar(ds.Spec.Template.Spec, common.NodeDaemonSetName, "FELIX_BPFENABLED")
	if dsBpfEnabledEnvVar != nil {
		dsBpfEnabledStatus, _ = strconv.ParseBool(*dsBpfEnabledEnvVar)
	}
	return dsBpfEnabledStatus
}

func bpfEnabledOnFelixConfig(fc *crdv1.FelixConfiguration) bool {
	return fc.Spec.BPFEnabled != nil && *fc.Spec.BPFEnabled
}
