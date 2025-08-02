// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

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
	"net"
	"reflect"
	"strconv"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"sigs.k8s.io/controller-runtime/pkg/client"

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
)

// bpfValidateAnnotations validate Felix Configuration annotations match BPF Enabled spec for all scenarios.
func bpfValidateAnnotations(fc *crdv1.FelixConfiguration) error {
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

// isRolloutCompleteWithBPFVolumes checks if the calico-node DaemonSet
// rollout process is completed with BPF volume mount been created.
// If the Installation resource has been patched to dataplane: BPF then the
// calico-node daemonset will be re-created with BPF infrastructure such as
// the "bpffs" volumne mount etc. which will cause the DS to do a rolling update.
// Therefore, one way to check that the daemonset rolling update is complete is
// to compare the DS status current scheduled pods equals the updated number and
// the current scheduled pods also equals the number available.  When all these
// checks are reconciled then FelixConfig can be patched as bpfEnabled: true.
func isRolloutCompleteWithBPFVolumes(ds *appsv1.DaemonSet) bool {
	for _, volume := range ds.Spec.Template.Spec.Volumes {
		if volume.Name == render.BPFVolumeName {
			//return ds.Status.CurrentNumberScheduled == ds.Status.UpdatedNumberScheduled && ds.Status.CurrentNumberScheduled == ds.Status.NumberAvailable
			if ds.Status.CurrentNumberScheduled == ds.Status.UpdatedNumberScheduled && ds.Status.CurrentNumberScheduled == ds.Status.NumberAvailable {
				return true
			} else {
				return false
			}
		}
	}
	return false
}

func setBPFEnabledOnFelixConfiguration(fc *crdv1.FelixConfiguration, bpfEnabled bool) error {
	err := bpfValidateAnnotations(fc)
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

func bpfEnabledOnDaemonsetWithEnvVar(ds *appsv1.DaemonSet) (bool, error) {
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

func disableBPFHostConntrackBypass(fc *crdv1.FelixConfiguration) {
	hostConntrackBypassDisabled := false
	fc.Spec.BPFHostConntrackBypass = &hostConntrackBypassDisabled
}

type BPFAutoBootstrap struct {
	kubeProxyDs         *appsv1.DaemonSet
	k8sService          *corev1.Service
	k8sServiceEndpoints *discoveryv1.EndpointSliceList
}

// bpfAutoBootstrapRequirements checks whether the BPF auto-bootstrap requirements are met.
// If so, it retrieves the kube-proxy DaemonSet, the Kubernetes service, and its EndpointSlices, returning them in a BPFAutoBootstrap struct.
// If it's not possible to retrieve any of these resources, it returns an error.
func bpfAutoBootstrapRequirements(c client.Client, ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration) (*BPFAutoBootstrap, error) {
	// If the user didn't set BPFBootstrapMode, or set it to manual, so we don't need to do anything.
	if !install.Spec.BPFInstallModeAuto() {
		return nil, nil
	}

	// 1. Dataplane should be BPF.
	if !install.Spec.BPFEnabled() {
		return nil, fmt.Errorf("the linuxDataplane is not BPF in Installation CR")
	}

	// 2. CNI plugin is Calico.
	if install.Spec.CNI.Type != operator.PluginCalico {
		return nil, fmt.Errorf("the CNI plugin is not Calico in Installation CR")
	}

	bpfBootstrapReq := &BPFAutoBootstrap{}
	// 3. Try to retrieve the kube-proxy DaemonSet.
	ds := &appsv1.DaemonSet{}
	err := c.Get(ctx, types.NamespacedName{Namespace: "kube-system", Name: "kube-proxy"}, ds)
	if err != nil {
		return nil, fmt.Errorf("failed to get kube-proxy: %w", err)
	}
	bpfBootstrapReq.kubeProxyDs = ds

	// 4. Try to retrieve kubernetes service.
	service := &corev1.Service{}
	err = c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubernetes"}, service)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes service: %w", err)
	}
	bpfBootstrapReq.k8sService = service

	// 5. Try to retrieve kubernetes service endpoint slices. If the cluster is dual-stack, there should be at least one EndpointSlice for each address type.
	endpointSlice := &discoveryv1.EndpointSliceList{}
	err = c.List(ctx, endpointSlice, client.InNamespace("default"), client.MatchingLabels{"kubernetes.io/service-name": "kubernetes"})
	if err != nil || len(endpointSlice.Items) == 0 {
		return nil, fmt.Errorf("failed to get kubernetes endpoint slices: %w", err)
	}
	bpfBootstrapReq.k8sServiceEndpoints = endpointSlice

	if err = validateIpFamilyConsistency(service, endpointSlice); err != nil {
		return nil, err
	}

	return bpfBootstrapReq, nil
}

// validateIpFamilyConsistency checks whether the service and EndpointSliceList have consistent IP address families.
func validateIpFamilyConsistency(service *corev1.Service, endpointSliceList *discoveryv1.EndpointSliceList) error {

	// Validating EndpointSlice IPs.
	epHasIPv4, epHasIPv6 := false, false
nestedLoop:
	for _, slice := range endpointSliceList.Items {
		for _, endpoint := range slice.Endpoints {
			for _, addr := range endpoint.Addresses {
				ip := net.ParseIP(addr)
				if ip == nil {
					return fmt.Errorf("Endpoint has an invalid IP: %s", addr)
				}

				if ip.To4() != nil {
					epHasIPv4 = true
				} else {
					epHasIPv6 = true
				}

				if epHasIPv4 && epHasIPv6 {
					break nestedLoop
				}
			}
		}
	}

	// Validating Service IPs.
	svcHasIPv4, svcHasIPv6 := false, false
	ips := service.Spec.ClusterIPs
	if len(ips) == 0 && service.Spec.ClusterIP != "" {
		ips = []string{service.Spec.ClusterIP}
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("service has an invalid IP: %s", ipStr)
		}

		if ip.To4() != nil {
			svcHasIPv4 = true
		} else {
			svcHasIPv6 = true
		}
	}

	var errV4, errV6 error
	if svcHasIPv4 != epHasIPv4 {
		errV4 = fmt.Errorf("service and EndpointSlice have inconsistent IPv4 configuration")
	}
	if svcHasIPv6 != epHasIPv6 {
		errV6 = fmt.Errorf("service and EndpointSlice have inconsistent IPv6 configuration")
	}

	return errors.Join(errV4, errV6)
}
