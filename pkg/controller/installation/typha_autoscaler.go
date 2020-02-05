// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	"time"
)

var typhaLog = logf.Log.WithName("typha_autoscaler")

const (
	defaultTyphaAutoscalerSyncPeriod = 2 * time.Minute
)

// typhaAutoscaler periodically lists the nodes and, if needed, scales the Typha deployment up/down.
// The number of Typha replicas depends on the number of nodes:
// Nodes       Replicas
//     1              1
//     2              2
//     3              3
//   250              4
//   500              5
//  1000              6
//  1500              7
//  2000              8
//  2000+            10
type typhaAutoscaler struct {
	client     client.Client
	syncPeriod time.Duration
}

type typhaAutoscalerOption func(*typhaAutoscaler)

// typhaAutoscalerPeriod is an option that sets a custom sync period for the Typha autoscaler.
func typhaAutoscalerPeriod(syncPeriod time.Duration) typhaAutoscalerOption {
	return func(t *typhaAutoscaler) {
		t.syncPeriod = syncPeriod
	}
}

// newTyphaAutoscaler creates a new Typha autoscaler, optionally applying any options to the default autoscaler instance.
// The default sync period is 2 minutes.
func newTyphaAutoscaler(client client.Client, options ...typhaAutoscalerOption) *typhaAutoscaler {
	ta := new(typhaAutoscaler)
	ta.client = client
	ta.syncPeriod = defaultTyphaAutoscalerSyncPeriod

	for _, option := range options {
		option(ta)
	}
	return ta
}

// getExpectedReplicas gets the number of replicas expected for a given node number.
func (t *typhaAutoscaler) getExpectedReplicas(nodes int) int {
	switch {
	case nodes <= 1:
		return 1
	case nodes <= 2:
		return 2
	case nodes <= 3:
		return 3
	case nodes <= 250:
		return 4
	case nodes <= 500:
		return 5
	case nodes <= 1000:
		return 6
	case nodes <= 1500:
		return 7
	case nodes <= 2000:
		return 8
	}
	return 10
}

// run starts the Typha autoscaler, updating the Typha deployment's replica count every sync period.
func (t *typhaAutoscaler) run() {
	ticker := time.NewTicker(t.syncPeriod)
	go func() {
		for {
			select {
			case <-ticker.C:
				expectedNodes, err := t.getNumberOfNodes()
				if err != nil {
					typhaLog.Error(err, "Could not get number of nodes")
					continue
				}
				expectedReplicas := t.getExpectedReplicas(expectedNodes)
				err = t.updateReplicas(int32(expectedReplicas))

				if err != nil && !apierrors.IsNotFound(err) {
					typhaLog.Error(err, "Could not scale Typha deployment")
				}
			}
		}
	}()
}

// updateReplicas updates the Typha deployment to the expected replicas if the current replica count differs.
func (t *typhaAutoscaler) updateReplicas(expectedReplicas int32) error {
	key := types.NamespacedName{Namespace: render.CalicoNamespace, Name: render.TyphaDeploymentName}
	typha := &appsv1.Deployment{}
	err := t.client.Get(context.Background(), key, typha)
	if err != nil {
		return err
	}

	// The replicas field defaults to 1. We need this in case spec.Replicas is nil.
	var prevReplicas int32
	prevReplicas = 1
	if typha.Spec.Replicas != nil {
		prevReplicas = *typha.Spec.Replicas
	}

	if prevReplicas == expectedReplicas {
		return nil
	}

	typhaLog.Info(fmt.Sprintf("Updating typha replicas from %d to %d", prevReplicas, expectedReplicas))
	typha.Spec.Replicas = &expectedReplicas
	return t.client.Update(context.Background(), typha)
}

// getNumberOfNodes returns the count of schedulable nodes.
func (t *typhaAutoscaler) getNumberOfNodes() (int, error) {
	nodes := corev1.NodeList{}
	err := t.client.List(context.Background(), &nodes)
	if err != nil {
		return 0, err
	}

	schedulable := 0
	for _, n := range nodes.Items {
		if !n.Spec.Unschedulable {
			schedulable++
		}
	}
	return schedulable, nil
}
