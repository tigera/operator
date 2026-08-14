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

package installation

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/sharedconfig"
)

const (
	// felixConfigFieldManager owns the FelixConfiguration fields defaulted from the Installation.
	felixConfigFieldManager = "installation"

	// bpfFieldManager owns spec.bpfEnabled, which both installation write sites declare.
	bpfFieldManager = "installation-bpf"
)

// declareFelixConfiguration declares the fields defaulted from the Installation spec, always
// declaring every one so the field set stays stable.
func (r *ReconcileInstallation) declareFelixConfiguration(install *operatorv1.Installation) sharedconfig.DeclareFelixConfiguration {
	return func(current *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
		d := &sharedconfig.FelixConfigurationDeclaration{
			Manager:  felixConfigFieldManager,
			Owned:    &v3.FelixConfiguration{},
			Policies: map[string]sharedconfig.ConflictPolicy{},
		}
		owned := &d.Owned.Spec

		// Keep calico-node's route tables clear of the ones the CNI plugin uses.
		switch install.Spec.CNI.Type {
		case operatorv1.PluginAmazonVPC:
			// AWS uses the ENI device number + 1, and the VLAN table ID + 100.
			owned.RouteTableRange = &v3.RouteTableRange{Min: 65, Max: 99}
			d.Policies["spec.routeTableRange"] = sharedconfig.ConflictDefer
		case operatorv1.PluginGKE:
			owned.RouteTableRange = &v3.RouteTableRange{Min: 10, Max: 250}
			d.Policies["spec.routeTableRange"] = sharedconfig.ConflictDefer
		}

		healthPort := 9099
		if install.Spec.KubernetesProvider.IsOpenShift() {
			healthPort = 9199
		}
		owned.HealthPort = &healthPort
		d.Policies["spec.healthPort"] = sharedconfig.ConflictDefer

		vxlanVNI, vxlanPort := 4096, 4789
		if install.Spec.KubernetesProvider == operatorv1.ProviderDockerEE {
			// MKE's docker swarm VXLAN uses 4096/4789, and the clash deletes vxlan.calico.
			// MKE's docs recommend 10000.
			vxlanVNI = 10000
			if install.Spec.BPFEnabled() {
				// The eBPF dataplane's flow-based VXLAN device clashes with the host's VXLAN interface.
				vxlanPort = 8472

				// The eBPF dataplane only works with MKE when conntrack bypass is off.
				owned.BPFHostConntrackBypass = ptr.To(false)
				d.Policies["spec.bpfHostConntrackBypass"] = sharedconfig.ConflictDefer
			}
		}
		owned.VXLANVNI = &vxlanVNI
		owned.VXLANPort = &vxlanPort
		d.Policies["spec.vxlanVNI"] = sharedconfig.ConflictDefer
		d.Policies["spec.vxlanPort"] = sharedconfig.ConflictDefer

		if install.Spec.BPFEnabled() && !install.Spec.KubeProxyManagementEnabled() {
			// The platform's kube-proxy holds 10256, so Felix's healthz server would fail to bind.
			owned.BPFKubeProxyHealthzPort = ptr.To(0)
			d.Policies["spec.bpfKubeProxyHealthzPort"] = sharedconfig.ConflictDefer
		}

		if install.Spec.CalicoNetwork != nil && install.Spec.CalicoNetwork.LinuxDataplane != nil {
			owned.NFTablesMode = ptr.To(nftablesMode(install))
			d.Policies["spec.nftablesMode"] = sharedconfig.ConflictOverride
		}

		if mode := clusterRoutingMode(install); mode != "" {
			owned.ProgramClusterRoutes = ptr.To(felixProgramClusterRoutesValue(mode))
			d.Policies["spec.programClusterRoutes"] = sharedconfig.ConflictOverride
		}

		extPaths, err := r.ext.DeclareFelixConfiguration(&install.Spec, current, d.Owned)
		if err != nil {
			return nil, err
		}
		for _, path := range extPaths {
			d.Policies[path] = sharedconfig.ConflictOverride
		}

		return d, nil
	}
}

// nftablesMode is the dataplane mode Felix should run in. The operator has always owned it,
// so nothing older needs preserving.
func nftablesMode(install *operatorv1.Installation) v3.NFTablesMode {
	if !install.Spec.IsNftables() {
		return v3.NFTablesModeDisabled
	}
	if install.Spec.BPFEnabled() {
		// BPF mode replaces kube-proxy, so nftables needs no compatibility with its mode.
		return v3.NFTablesModeEnabled
	}
	// kube-proxy is running, so let Felix pick per node and keep upgrades smooth.
	return v3.NFTablesModeAuto
}

// declareBPFEnabled declares spec.bpfEnabled. Both installation write sites use it so the field
// stays under one manager with the same value.
func (r *ReconcileInstallation) declareBPFEnabled(ctx context.Context, install *operatorv1.Installation, needNsMigration bool) sharedconfig.DeclareFelixConfiguration {
	return func(current *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
		enabled, err := r.bpfEnabledValue(ctx, install, current, needNsMigration)
		if err != nil {
			return nil, err
		}
		return &sharedconfig.FelixConfigurationDeclaration{
			Manager: bpfFieldManager,
			Owned: &v3.FelixConfiguration{
				Spec: v3.FelixConfigurationSpec{BPFEnabled: &enabled},
			},
			Policies: map[string]sharedconfig.ConflictPolicy{
				// A user who changed this by hand gets a degraded status, not an override.
				"spec.bpfEnabled": sharedconfig.ConflictError,
			},
		}, nil
	}
}

// bpfEnabledValue resolves the dataplane Felix should run. Turning eBPF on waits for the
// calico-node rollout to mount the BPF volumes.
func (r *ReconcileInstallation) bpfEnabledValue(ctx context.Context, install *operatorv1.Installation, current *v3.FelixConfiguration, needNsMigration bool) (bool, error) {
	if !install.Spec.BPFEnabled() {
		return false, nil
	}

	ds := &appsv1.DaemonSet{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: common.CalicoNamespace, Name: common.NodeDaemonSetName}, ds)
	if apierrors.IsNotFound(err) {
		// A fresh install in eBPF mode has no calico-node rollout to wait for.
		return !needNsMigration, nil
	}
	if err != nil {
		return false, err
	}

	// Operators before the FelixConfiguration field enabled eBPF through a calico-node env var.
	envVarEnabled, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
	if err != nil {
		return false, err
	}
	if envVarEnabled || isRolloutCompleteWithBPFVolumes(ds) {
		return true, nil
	}
	return bpfEnabledOnFelixConfig(current), nil
}
