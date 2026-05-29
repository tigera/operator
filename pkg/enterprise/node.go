// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package enterprise

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	client "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/operator"
	"github.com/tigera/operator/pkg/render"
)

const (
	defaultNodeReporterPort    = 9081
	defaultFelixMetricsPort    = 9091
)

func registerNode() {
	operator.OverrideImage(render.ComponentNameNode, func(in *operatorv1.InstallationSpec) (components.Component, bool) {
		if !in.Variant.IsEnterprise() {
			return components.Component{}, false
		}
		return components.ComponentTigeraNode, true
	})
	operator.Patch(render.ComponentNameNode, patchNode)
}

func patchNode(ctx operator.Context, objs []client.Object) []client.Object {
	if ctx.Installation == nil || !ctx.Installation.Variant.IsEnterprise() {
		return objs
	}
	return append(objs, nodeMetricsService(ctx))
}

// nodeMetricsService builds the enterprise-only calico-node-metrics Service.
// Ports are derived from FelixConfiguration exactly as the installation controller does.
func nodeMetricsService(ctx operator.Context) *corev1.Service {
	reporterPort := defaultNodeReporterPort
	felixPort := defaultFelixMetricsPort
	felixEnabled := false
	if fc := ctx.FelixConfiguration; fc != nil {
		if fc.Spec.PrometheusReporterPort != nil {
			reporterPort = *fc.Spec.PrometheusReporterPort
		}
		if fc.Spec.PrometheusMetricsPort != nil {
			felixPort = *fc.Spec.PrometheusMetricsPort
		}
		felixEnabled = utils.IsFelixPrometheusMetricsEnabled(fc)
	}

	ports := []corev1.ServicePort{
		{
			Name:       "calico-metrics-port",
			Port:       int32(reporterPort),
			TargetPort: intstr.FromInt(reporterPort),
			Protocol:   corev1.ProtocolTCP,
		},
		{
			Name:       "calico-bgp-metrics-port",
			Port:       render.NodeBGPReporterPort,
			TargetPort: intstr.FromInt(int(render.NodeBGPReporterPort)),
			Protocol:   corev1.ProtocolTCP,
		},
	}
	if felixEnabled {
		ports = append(ports, corev1.ServicePort{
			Name:       "felix-metrics-port",
			Port:       int32(felixPort),
			TargetPort: intstr.FromInt(felixPort),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.CalicoNodeMetricsService,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": render.CalicoNodeObjectName},
		},
		Spec: corev1.ServiceSpec{
			Selector:  map[string]string{"k8s-app": render.CalicoNodeObjectName},
			ClusterIP: "None",
			Ports:     ports,
		},
	}
}
