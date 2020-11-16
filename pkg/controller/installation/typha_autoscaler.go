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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
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
	client         client.Client
	syncPeriod     time.Duration
	statusManager  status.StatusManager
	triggerRunChan chan chan error
	isDegradedChan chan chan bool
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
func newTyphaAutoscaler(client client.Client, statusManager status.StatusManager, options ...typhaAutoscalerOption) *typhaAutoscaler {
	ta := &typhaAutoscaler{
		client:         client,
		statusManager:  statusManager,
		syncPeriod:     defaultTyphaAutoscalerSyncPeriod,
		triggerRunChan: make(chan chan error),
		isDegradedChan: make(chan chan bool),
	}

	for _, option := range options {
		option(ta)
	}
	return ta
}

// start starts the Typha autoscaler, updating the Typha deployment's replica count every sync period. The triggerRunChan
// can be used to trigger an auto scale run immediately, while the isDegradedChan can be used to get the degraded status
// of the last run. The triggerRun and isDegraded functions should be used instead of instead of access these channels directly.
func (t *typhaAutoscaler) start() {
	go func() {
		degraded := false
		ticker := time.NewTicker(t.syncPeriod)
		defer ticker.Stop()

		if err := t.autoscaleReplicas(); err != nil {
			degraded = true
			typhaLog.Error(err, "Failed to autoscale typha")
			t.statusManager.SetDegraded("Failed to autoscale typha", err.Error())
		}

		// Autoscale on start up then do it again every tick.
		for {
			select {
			case <-ticker.C:
				if err := t.autoscaleReplicas(); err != nil {
					degraded = true
					typhaLog.Error(err, "Failed to autoscale typha")

					// Since this run was triggered by the ticker we need to degrade the tigera status now.
					t.statusManager.SetDegraded("Failed to autoscale typha", err.Error())
				} else {
					degraded = false
				}
			case errCh := <-t.triggerRunChan:
				if err := t.autoscaleReplicas(); err != nil {
					degraded = true

					// Return the error so the "caller" can decided what to do with the error
					errCh <- err
				} else {
					degraded = false
				}

				close(errCh)

				ticker.Stop()
				ticker = time.NewTicker(t.syncPeriod)
			case boolCh := <-t.isDegradedChan:
				boolCh <- degraded
				close(boolCh)
			}
		}
	}()
}

func (t *typhaAutoscaler) triggerRun() error {
	errChan := make(chan error)
	t.triggerRunChan <- errChan

	return <-errChan
}

// isDegraded checks if the last run autoscale run failed and returns true if it did and false otherwise.
func (t *typhaAutoscaler) isDegraded() bool {
	boolChan := make(chan bool)
	t.isDegradedChan <- boolChan

	return <-boolChan
}

// autoscaleReplicas calculates the number of typha pods that should be running and scales the typha deployment accordingly
func (t *typhaAutoscaler) autoscaleReplicas() error {
	allSchedulableNodes, linuxNodes, err := t.getNodeCounts()
	if err != nil {
		return fmt.Errorf("could not get number of nodes: %w", err)
	}
	expectedReplicas := utils.GetExpectedTyphaScale(allSchedulableNodes)
	if linuxNodes < expectedReplicas {
		return fmt.Errorf("not enough linux nodes to schedule typha pods on, require %d and have %d", expectedReplicas, linuxNodes)
	}

	err = t.updateReplicas(int32(expectedReplicas))

	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("could not scale Typha deployment: %w", err)
	}

	return nil
}

// updateReplicas updates the Typha deployment to the expected replicas if the current replica count differs.
func (t *typhaAutoscaler) updateReplicas(expectedReplicas int32) error {
	key := types.NamespacedName{Namespace: common.CalicoNamespace, Name: common.TyphaDeploymentName}
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

// getNodeCounts returns the number of all the schedulable nodes and the number of the schedulable linux nodes. The linux
// node count is needed because typha pods can only be scheduled on linux nodes, however, nodes of other os types (i.e. windows)
// still need to use typha.
func (t *typhaAutoscaler) getNodeCounts() (int, int, error) {
	nodes := corev1.NodeList{}
	// We only want to count linux nodes
	err := t.client.List(context.Background(), &nodes)
	if err != nil {
		return 0, 0, err
	}

	linuxNodes := 0
	schedulable := 0
	for _, n := range nodes.Items {
		if !n.Spec.Unschedulable {
			schedulable++
			if n.Labels["kubernetes.io/os"] == "linux" {
				linuxNodes++
			}
		}
	}
	return schedulable, linuxNodes, nil
}

func (t *typhaAutoscaler) getSchedulableNodeCount(listOptions ...client.ListOption) (int, error) {
	nodes := corev1.NodeList{}
	err := t.client.List(context.Background(), &nodes, listOptions...)
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
