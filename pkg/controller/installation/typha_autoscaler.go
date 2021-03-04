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
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
)

var typhaLog = logf.Log.WithName("typha_autoscaler")

const (
	defaultTyphaAutoscalerSyncPeriod = 10 * time.Second
)

// typhaAutoscaler periodically lists the nodes and, if needed, scales the Typha deployment up/down.
// Number of replicas should be at least (1 typha for every 200 nodes) + 1 but the number of typhas
// cannot exceed the number of nodes+masters.
// Nodes       Replicas
//     1              1
//     2              2
//  <200              3
//  >400              4
//  >600              5
//  >800              6
// >1000              7
//    .....
// >2000              12
//    .....
// >3600             20
type typhaAutoscaler struct {
	client         client.Client
	syncPeriod     time.Duration
	statusManager  status.StatusManager
	triggerRunChan chan chan error
	isDegradedChan chan chan bool
	informer       cache.Controller
	indexer        cache.Indexer

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
// The default sync period is 15 seconds.
func newTyphaAutoscaler(cfg *rest.Config, client client.Client, statusManager status.StatusManager, options ...typhaAutoscalerOption) *typhaAutoscaler {
	// Create a Node watcher to signal us when nodes are updated.
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "Unable to build typha autoscaler")
		return nil
	}
	listWatcher := cache.NewListWatchFromClient(cs.CoreV1().RESTClient(), "nodes", "", fields.Everything())
	handlers := cache.ResourceEventHandlerFuncs{AddFunc: func(obj interface{}) {}}
	nodeIndexer, nodeInformer := cache.NewIndexerInformer(listWatcher, &v1.Node{}, 0, handlers, cache.Indexers{})
	ta := &typhaAutoscaler{
		client:         client,
		statusManager:  statusManager,
		syncPeriod:     defaultTyphaAutoscalerSyncPeriod,
		triggerRunChan: make(chan chan error),
		isDegradedChan: make(chan chan bool),
		indexer:        nodeIndexer,
		informer:       nodeInformer,
	}

	// Configure an informer to monitor the active replicas.
	typhaWatcher := cache.NewListWatchFromClient(cs.AppsV1().RESTClient(), "deployments", "calico-system", fields.Everything()) //fields.OneTermEqualSelector("metadata.name", "calico-typha"))
	typhaHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ta.activeReplicas = *obj.(*appsv1.Deployment).Spec.Replicas
		},
		UpdateFunc: func(old, obj interface{}) {
			ta.activeReplicas = *obj.(*appsv1.Deployment).Spec.Replicas
		},
	}
	_, typhaInformer := cache.NewIndexerInformer(typhaWatcher, &appsv1.Deployment{}, 0, typhaHandlers, cache.Indexers{})

	for _, option := range options {
		option(ta)
	}

	// Start the informers and wait for them to sync.
	stopCh := make(chan struct{})
	go nodeInformer.Run(stopCh)
	go typhaInformer.Run(stopCh)
	for !nodeInformer.HasSynced() && !typhaInformer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
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
		log.Info("Starting typha autoscaler", "syncPeriod", t.syncPeriod)

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
	log.V(1).Info("Number of nodes to consider for typha autoscaling", "all", allSchedulableNodes, "linux", linuxNodes)
	expectedReplicas := common.GetExpectedTyphaScale(allSchedulableNodes)
	if linuxNodes < expectedReplicas {
		return fmt.Errorf("not enough linux nodes to schedule typha pods on, require %d and have %d", expectedReplicas, linuxNodes)
	}

	log.V(1).Info("Checking if we need to scale typha", "expectedReplicas", expectedReplicas, "currentReplicas", t.activeReplicas)
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
	linuxNodes := 0
	schedulable := 0
	for _, obj := range t.indexer.List() {
		n := obj.(*v1.Node)
		if n.Spec.Unschedulable {
			continue
		}
		if n.GetObjectMeta().GetAnnotations()["projectcalico.org/operator-node-migration"] == "pre-operator" {
			// This node hasn't been migrated to the operator yet. Don't include it in the number of desired Typhas.
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
