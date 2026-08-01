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

package apiserver

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
)

// calicoAPIServiceName is the aggregated API registration for projectcalico.org/v3.
const calicoAPIServiceName = "v3.projectcalico.org"

// deprecatedAPIServerNamespace is where the API server ran before it was rehomed into
// calico-system.
const deprecatedAPIServerNamespace = "tigera-system"

// apiServerLayout says which API server the aggregated projectcalico.org/v3 API is
// currently registered against.
type apiServerLayout int

const (
	// layoutAbsent means there is no APIService yet: a fresh install.
	layoutAbsent apiServerLayout = iota
	// layoutDeprecated means the APIService still points into tigera-system, so the
	// migration has not been performed.
	layoutDeprecated
	// layoutCurrent means the APIService points into calico-system.
	layoutCurrent
)

// readAPIServiceState reports which API server layout is registered and whether the
// aggregated API can currently serve requests.
//
// Both answers come from the APIService, which is an apiregistration.k8s.io object served
// by the kube-apiserver itself. Reading it therefore does not depend on the aggregated API
// being healthy, which is the whole point: it is the one place that can tell us the
// aggregated API is down. spec.service.namespace gives the layout; the Available condition
// is the kube-aggregator's own verdict on whether requests can be served.
func readAPIServiceState(ctx context.Context, reader client.Reader) (apiServerLayout, bool, error) {
	as := &apiregv1.APIService{}
	if err := reader.Get(ctx, client.ObjectKey{Name: calicoAPIServiceName}, as); err != nil {
		if apierrors.IsNotFound(err) {
			return layoutAbsent, false, nil
		}
		return layoutAbsent, false, err
	}

	layout := layoutCurrent
	if as.Spec.Service != nil && as.Spec.Service.Namespace == deprecatedAPIServerNamespace {
		layout = layoutDeprecated
	}

	available := false
	for _, c := range as.Status.Conditions {
		if c.Type == apiregv1.Available {
			available = c.Status == apiregv1.ConditionTrue
			break
		}
	}
	return layout, available, nil
}

// denyReadTimeout bounds the one read in this file that is proxied to the aggregated API
// server. The APIService read is served by the kube-apiserver itself and needs no bound, but
// this Get goes through the aggregator to the Calico API server, and the reconcile worker is
// single-threaded: an unbounded read against a backend that has just stopped answering would
// stall every other reconcile in this controller.
const denyReadTimeout = 15 * time.Second

// deprecatedDenyPresent reports whether allow-tigera.default-deny still exists in the
// calico-system namespace. That policy sits in the earlier-evaluated allow-tigera tier and
// selects all() endpoints, so while it exists it denies the migrated calico-apiserver pod
// at end-of-tier before the calico-system tier is ever consulted.
//
// Only NotFound means "absent". A NoMatch error means the RESTMapper has no mapping for the
// kind, which is not evidence about the policy, so it is returned rather than treated as an
// absence that would license the move.
func deprecatedDenyPresent(ctx context.Context, reader client.Reader) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, denyReadTimeout)
	defer cancel()

	deny := networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", render.APIServerNamespace)
	if err := reader.Get(ctx, client.ObjectKeyFromObject(deny), deny); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// migrationDecision is what the controller should do about the API server migration on this
// pass.
type migrationDecision int

const (
	// decisionProceed means reconcile normally.
	decisionProceed migrationDecision = iota
	// decisionWaitForDenyRemoval means a migration is pending and safe to make, but the
	// deprecated deny that would trap the moved pod is still in place. The
	// installation controller removes it through the still-serving API server.
	decisionWaitForDenyRemoval
	// decisionHoldAPIUnavailable means a migration is pending but the aggregated API cannot
	// serve, so we can neither verify the trap is gone nor rely on anything clearing it.
	// Applying the move now would repoint the aggregated API onto a pod we cannot vouch for.
	decisionHoldAPIUnavailable
)

// decideMigration decides what to do about the migration from the live state.
//
// A migration is pending only when the APIService still points into the deprecated
// namespace. Keying on that rather than on the deny's presence matters: a two-hop upgrade
// through CE 3.22 leaves the deny in place, with a selector that excludes the API server,
// after the move has already happened. Asking about the policy there would hold a migration
// that is already complete.
func decideMigration(layout apiServerLayout, aggregatedAPIAvailable, denyPresent bool) migrationDecision {
	if layout != layoutDeprecated {
		return decisionProceed
	}
	// This is a pre-filter, not a guarantee: the condition reflects a probe from up to
	// ~30s ago. What actually proves the API can serve is the caller's uncached Get of the
	// deprecated deny, made immediately before this function is called and only when this
	// condition is true: that Get is served by the aggregated API itself, so it errors
	// rather than returning a decoded answer if the API cannot serve, and the caller
	// returns before decideMigration ever runs. So a stale "true" cannot make it here as a
	// false denyPresent, and a stale "false" only costs an unneeded hold - it is never
	// wrong to wait a bit longer.
	if !aggregatedAPIAvailable {
		return decisionHoldAPIUnavailable
	}
	if denyPresent {
		return decisionWaitForDenyRemoval
	}
	return decisionProceed
}

// policyComponentFirst reports whether the projectcalico.org/v3 NetworkPolicy component
// should be applied before the API server workload.
//
// It is rendered last normally, so that a fresh install is not blocked on an API server that
// cannot become available until the install has progressed. On the pass that performs the
// migration that ordering leaves the moved pod running with no policy of its own, and by
// then we have established that the aggregated API can serve, so the policy can go first.
func policyComponentFirst(moveIsPending, renderPolicy bool) bool {
	return moveIsPending && renderPolicy
}
