// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var typhaLog = logf.Log.WithName("typha_autoscaler")

const (
	defaultTyphaAutoscalerSyncPeriod = 10 * time.Second
)

// typhaAutoscaler periodically lists the nodes and, if needed, scales the Typha deployment up/down.
// Number of replicas should be at least (1 typha for every 200 nodes) + 1 but the number of typhas
// cannot exceed the number of nodes+masters.
type typhaAutoscaler struct {
	client            kubernetes.Interface
	syncPeriod        time.Duration
	statusManager     status.StatusManager
	triggerRunChan    chan chan error
	isDegradedChan    chan chan bool
	nodeIndexInformer cache.SharedIndexInformer
	typhaInformer     cache.Controller
	typhaIndexer      cache.Indexer

	// Number of currently running replicas.
	activeReplicas int32
}

type typhaAutoscalerOption func(*typhaAutoscaler)

// typhaAutoscalerPeriod is an option that sets a custom sync period for the Typha autoscaler.
func typhaAutoscalerPeriod(syncPeriod time.Duration) typhaAutoscalerOption {
	return func(t *typhaAutoscaler) {
		t.syncPeriod = syncPeriod
	}
}

// newTyphaAutoscaler creates a new Typha autoscaler, optionally applying any options to the default autoscaler instance.
// The default sync period is 10 seconds.
func newTyphaAutoscaler(cs kubernetes.Interface, nodeIndexInformer cache.SharedIndexInformer, typhaListWatch cache.ListerWatcher, statusManager status.StatusManager, options ...typhaAutoscalerOption) *typhaAutoscaler {
	ta := &typhaAutoscaler{
		client:            cs,
		statusManager:     statusManager,
		syncPeriod:        defaultTyphaAutoscalerSyncPeriod,
		triggerRunChan:    make(chan chan error),
		isDegradedChan:    make(chan chan bool),
		nodeIndexInformer: nodeIndexInformer,
	}

	// Configure an informer to monitor the active replicas.
	typhaHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if d, ok := obj.(*appsv1.Deployment); ok {
				if d.Spec.Replicas != nil {
					ta.activeReplicas = *d.Spec.Replicas
				}
			}
		},
		UpdateFunc: func(old, obj interface{}) {
			if d, ok := obj.(*appsv1.Deployment); ok {
				if d.Spec.Replicas != nil {
					ta.activeReplicas = *d.Spec.Replicas
				}
			}
		},
	}
	ta.typhaIndexer, ta.typhaInformer = cache.NewIndexerInformer(typhaListWatch, &appsv1.Deployment{}, 0, typhaHandlers, cache.Indexers{})

	for _, option := range options {
		option(ta)
	}
	return ta
}

// start starts the Typha autoscaler, updating the Typha deployment's replica count every sync period. The triggerRunChan
// can be used to trigger an auto scale run immediately, while the isDegradedChan can be used to get the degraded status
// of the last run. The triggerRun and isDegraded functions should be used instead of instead of access these channels directly.
func (t *typhaAutoscaler) start(ctx context.Context) {
	go func() {
		degraded := false
		ticker := time.NewTicker(t.syncPeriod)
		defer ticker.Stop()
		typhaLog.Info("Starting typha autoscaler", "syncPeriod", t.syncPeriod)

		// Start the informer.
		go t.typhaInformer.Run(ctx.Done())
		// Wait for the informers to sync.
		for !t.nodeIndexInformer.HasSynced() || !t.typhaInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}

		// Autoscale on start up then do it again every tick.
		if err := t.autoscaleReplicas(); err != nil {
			degraded = true
			typhaLog.Error(err, "Failed to autoscale typha")
			t.statusManager.SetDegraded(operator.ResourceScalingError, fmt.Sprintf("Failed to autoscale typha - %s", err.Error()), nil, log)
		}

		for {
			select {
			case <-ticker.C:
				if err := t.autoscaleReplicas(); err != nil {
					degraded = true
					typhaLog.Error(err, "Failed to autoscale typha")

					// Since this run was triggered by the ticker we need to degrade the tigera status now.
					t.statusManager.SetDegraded(operator.ResourceScalingError, fmt.Sprintf("Failed to autoscale typha - %s", err.Error()), nil, log)
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
			case <-ctx.Done():
				typhaLog.Info("typha autoscaler shutting down")
				return
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
	typhaLog.V(5).Info("Number of nodes to consider for typha autoscaling", "all", allSchedulableNodes, "linux", linuxNodes)
	expectedReplicas := common.GetExpectedTyphaScale(allSchedulableNodes)
	if linuxNodes < expectedReplicas {
		return fmt.Errorf("not enough linux nodes to schedule typha pods on, require %d and have %d", expectedReplicas, linuxNodes)
	}

	typhaLog.V(5).Info("Checking if we need to scale typha", "expectedReplicas", expectedReplicas, "currentReplicas", t.activeReplicas)
	if int32(expectedReplicas) != t.activeReplicas {
		err = t.updateReplicas(int32(expectedReplicas))
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("could not scale Typha deployment: %w", err)
		}
	}

	return nil
}

// updateReplicas updates the Typha deployment to the expected replicas if the current replica count differs.
func (t *typhaAutoscaler) updateReplicas(expectedReplicas int32) error {
	typha, err := t.client.AppsV1().Deployments(common.CalicoNamespace).Get(context.Background(), common.TyphaDeploymentName, metav1.GetOptions{})
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
	_, err = t.client.AppsV1().Deployments(common.CalicoNamespace).Update(context.Background(), typha, metav1.UpdateOptions{})
	return err
}

// getNodeCounts returns the number of all the schedulable nodes and the number of the schedulable linux nodes. The linux
// node count is needed because typha pods can only be scheduled on linux nodes, however, nodes of other os types (i.e. windows)
// still need to use typha.
func (t *typhaAutoscaler) getNodeCounts() (int, int, error) {
	linuxNodes := 0
	schedulable := 0
	for _, obj := range t.nodeIndexInformer.GetIndexer().List() {
		n := obj.(*v1.Node)
		if n.Spec.Unschedulable {
			continue
		}

		if _, ok := n.Labels["kubernetes.azure.com/cluster"]; ok && n.Labels["type"] == "virtual-kubelet" {
			// in AKS, there is a feature called 'virtual-nodes' which represent azure's container service as a node in the kubernetes cluster.
			// virtual-nodes have many limitations, and are tainted to prevent pods from running on them.
			// calico-node isn't run there as they don't support hostNetwork or host volume mounts.
			// as such, we shouldn't consider virtual-nodes in the count towards how many typha pods should be run.
			// furthermore, typha can't run on virtual-nodes as it is hostnetworked, so we don't want it's desired
			// replica count to include it.
			continue
		}

		schedulable++
		if n.Labels["kubernetes.io/os"] == "linux" {
			linuxNodes++
		}
	}
	return schedulable, linuxNodes, nil
}
