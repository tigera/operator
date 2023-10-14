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

	"github.com/go-logr/logr"
	operator "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Adriana() (int, error) {
	//err := fmt.Errorf("this is a pretent errro")
	//return 8, err
	return 8, nil
}

func Adriana1(r *ReconcileInstallation, ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, log logr.Logger) error {
	return nil
}

//func Adriana1(ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, log logr.Logger) error
//return r.setStevepro(ctx, instance, felixConfiguration, reqLogger)
//}

func setStevepro(r *ReconcileInstallation, ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, log logr.Logger) error {

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
