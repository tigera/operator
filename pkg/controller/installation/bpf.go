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

	"github.com/go-logr/logr"
	operator "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/migration/convert"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func bpfUpgradeWithoutDisruption(r *ReconcileInstallation, ctx context.Context, install *operator.Installation, ds *appsv1.DaemonSet, fc *crdv1.FelixConfiguration, reqLogger logr.Logger) error {

	// Query calico-node DS: if FELIX_BPFENABLED env var set and FC bpfEnabled unset then patch FC and quit.
	patchFelixConfig, err := processDaemonsetEnvVar(r, ctx, ds, fc, reqLogger)
	if err != nil {
		return err
	}

	// Otherwise check dataplane and patch Felix Config according to logic:
	if !patchFelixConfig {

		// Check the install dataplane mode is either Iptables or BPF.
		installBpfEnabled := common.BpfDataplaneEnabled(&install.Spec)

		// Check edge case where User has externally patched FelixConfig bpfEnabled which causes conflict to prevent Operator from upgrading dataplane.
		if fc.Spec.BPFEnabled != nil {

			fcBPFEnabled := *fc.Spec.BPFEnabled
			if installBpfEnabled != fcBPFEnabled {

				// Ensure Felix Config annotations are either empty or equal previous FC bpfEnabled value.
				if fc.Annotations[render.BpfOperatorAnnotation] == strconv.FormatBool(installBpfEnabled) {
					text := fmt.Sprintf("An error occurred while attempting patch Felix Config bpfEnabled: '%s' as Felix Config has been modified externally to '%s'",
						strconv.FormatBool(installBpfEnabled),
						strconv.FormatBool(fcBPFEnabled))
					err = errors.New(text)
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
		if patchFelixConfig {

			err = patchFelixConfiguration(r, ctx, fc, reqLogger, installBpfEnabled)
			if err != nil {
				return err
			}

			// Ensure if no errors occurred while attempting to patch Falix Config then successfully patched.
			patchFelixConfig = err == nil
		}
	}

	if patchFelixConfig {
		if fc.Spec.BPFEnabled != nil {
			msg := fmt.Sprintf("Successfully patched Felix Config OK bpfEnabled='%s'", strconv.FormatBool(*fc.Spec.BPFEnabled))
			reqLogger.Info(msg)
		}
	}

	return nil
}

func processDaemonsetEnvVar(r *ReconcileInstallation, ctx context.Context, ds *appsv1.DaemonSet, fc *crdv1.FelixConfiguration, reqLogger logr.Logger) (bool, error) {

	dsBpfEnabledEnvVar, err := convert.GetEnv(ctx, r.client, ds.Spec.Template.Spec, convert.ComponentCalicoNode, common.NodeDaemonSetName, "FELIX_BPFENABLED")
	if err != nil {
		reqLogger.Error(err, "An error occurred when querying Calico-Node environment variable FELIX_BPFENABLED")
		return false, err
	}

	dsBpfEnabledStatus := false
	if dsBpfEnabledEnvVar != nil {
		dsBpfEnabledStatus, err = strconv.ParseBool(*dsBpfEnabledEnvVar)
		if err != nil {
			reqLogger.Error(err, "An error occurred when converting Calico-Node environment variable FELIX_BPFENABLED")
			return false, err
		}
	}

	if dsBpfEnabledStatus && fc.Spec.BPFEnabled == nil {
		err = patchFelixConfiguration(r, ctx, fc, reqLogger, dsBpfEnabledStatus)
		if err != nil {
			return false, err
		} else {
			return true, nil
		}
	}

	return false, nil
}

func checkDaemonsetRolloutComplete(ds *appsv1.DaemonSet) bool {
	return ds.Annotations != nil && ds.Annotations[render.BpfOperatorAnnotation] == "true"
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
