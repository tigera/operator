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
	"fmt"
	"strconv"

	"github.com/go-logr/logr"
	operator "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/migration/convert"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func bpfUpgradeWithoutDisruption(r *ReconcileInstallation, ctx context.Context, install *operator.Installation, ds *appsv1.DaemonSet, fc *crdv1.FelixConfiguration, reqLogger logr.Logger) error {

	// Extract
	dsBpfEnabledEnvVar, err := convert.GetEnv(ctx, r.client, ds.Spec.Template.Spec, convert.ComponentCalicoNode, common.NodeDaemonSetName, "FELIX_BPFENABLED")
	if err != nil {
		reqLogger.Error(err, "An error occurred when querying Calico-Node environment variable FELIX_BPFENABLED")

	}

	dsBpfEnabledStatus := false
	if dsBpfEnabledEnvVar != nil {
		dsBpfEnabledStatus, err = strconv.ParseBool(*dsBpfEnabledEnvVar)
		if err != nil {
			reqLogger.Error(err, "An error occurred when converting Calico-Node environment variable FELIX_BPFENABLED")
			return err
		}
	}

	// Use case #1
	if dsBpfEnabledStatus && fc.Spec.BPFEnabled == nil {
		err = patchFelixConfiguration(r, ctx, fc, reqLogger, dsBpfEnabledStatus)
		if err == nil {
			// TODO - better msg
			reqLogger.Info("Successfully patched FelixConfig")
		}
		return err
	}

	return err
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
		msg := fmt.Sprintf("An error occurred when attempting to patch Felix configuration BPF Enabled: '%s'\n", patchText)
		reqLogger.Error(err, msg)
		return err
	}

	return nil
}

func AdrianaX(ds *appsv1.DaemonSet) (string, error) {
	return "false", nil
}

func (r *ReconcileInstallation) Adriana1(ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, log logr.Logger) error {
	r.Adriana2(ctx, log)
	return setStevepro(r, ctx, install, fc, log)
}

// Exctract env var
func (r *ReconcileInstallation) Adriana2(ctx context.Context, log logr.Logger) error {
	var err error

	// Get the calico-node daemonset.
	calicoNodeDaemonset := appsv1.DaemonSet{}
	err = r.client.Get(ctx, types.NamespacedName{Namespace: common.CalicoNamespace, Name: common.NodeDaemonSetName}, &calicoNodeDaemonset)
	if err != nil {
		// TODO log error
		return err
	}

	// Attempt to extract the env var.
	bpfEnabledEnvVar, err := convert.GetEnv(ctx, r.client, calicoNodeDaemonset.Spec.Template.Spec, convert.ComponentCalicoNode, common.NodeDaemonSetName, "FELIX_BPFENABLED")
	if err != nil {
		log.Error(err, "An error occurred when querying Calico-Node environment variable FELIX_BPFENABLED")

	}
	bpfEnabledStatus := false
	if bpfEnabledEnvVar != nil {
		bpfEnabledStatus, err = strconv.ParseBool(*bpfEnabledEnvVar)
		if err != nil {
			log.Error(err, "An error occurred when converting Calico-Node environment variable FELIX_BPFENABLED")
			return err
		}
	}
	_ = bpfEnabledStatus

	return nil
}

func setStevepro(r *ReconcileInstallation, ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, log logr.Logger) error {
	patchFrom := client.MergeFrom(fc.DeepCopy())

	bpfEnabled := common.BpfDataplaneEnabled(&install.Spec)

	// Managed fields "light".
	var fcAnnotations map[string]string
	if fc.Annotations == nil {
		fcAnnotations = make(map[string]string)
	} else {
		fcAnnotations = fc.Annotations
	}
	fcAnnotations[render.BpfOperatorAnnotation] = "true"
	fc.SetAnnotations(fcAnnotations)

	// TODO - check from #1
	//bpfEnabled = false
	fc.Spec.BPFEnabled = &bpfEnabled
	if err := r.client.Patch(ctx, fc, patchFrom); err != nil {
		log.Info("adriana-1.30.64 setStevepro ERROR:")
		return err
	}
	return nil
}

/*
func setStevepro1(r *ReconcileInstallation, ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, log logr.Logger) error {

	log.Info("adriana-1.30.64 setStevepro beg")
	patchFrom := client.MergeFrom(fc.DeepCopy())

	if fc.Annotations != nil {
		an := fc.Annotations
		an[render.BpfOperatorAnnotation] = "true"
		fc.SetAnnotations(an)
	}

	log.Info("adriana-1.30.64 setStevepro bpf BEG")
	bpfEnabled := common.BpfDataplaneEnabled(&install.Spec)
	if bpfEnabled {
		log.Info("adriana-1.30.64 setStevepro bpf val=TRUE")
	} else {
		log.Info("adriana-1.30.64 setStevepro bpf val=false")
	}
	//log.Info("adriana-1.30.64 setStevepro bpf val", bpfEnabled)
	log.Info("adriana-1.30.64 setStevepro bpf end")
	//bpfEnabled := true
	fc.Spec.BPFLogLevel = "Info"
	fc.Spec.BPFEnabled = &bpfEnabled
	if err := r.client.Patch(ctx, fc, patchFrom); err != nil {
		log.Info("adriana-1.30.64 setStevepro ERROR:")
		return err
	}
	log.Info("adriana-1.30.64 setStevepro patched:")
	log.Info("adriana-1.30.64 setStevepro end")

	return nil
}
*/
