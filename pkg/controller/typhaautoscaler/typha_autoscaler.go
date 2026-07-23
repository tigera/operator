// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

// Package typhaautoscaler scales a Typha-like deployment to track the size of
// the thing it fans out to: the cluster's node count for the in-cluster Typha,
// or the registered-host (HostEndpoint) count for the non-cluster-host Typha
// and the Serval gateway. Controllers own the deployment they scale; this
// package only adjusts its replica count.
package typhaautoscaler

import (
	"context"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
)

var typhaLog = logf.Log.WithName("typha_autoscaler")

const (
	defaultSyncPeriod = 10 * time.Second

	hepCreatedLabelKey   = "projectcalico.org/created-by"
	hepCreatedLabelValue = "calico-kube-controllers"
)

// Autoscaler periodically counts the nodes (or host endpoints) and, if needed, scales its
// deployment(s) to match. Number of replicas should be at least (1 typha for every 200 nodes) + 1
// but the number of typhas cannot exceed the number of nodes+masters. It can drive more than one
// deployment from the same count — the non-cluster-host controller scales the serval gateway and
// the legacy calico-typha-noncluster-host deployment with one instance, since exactly one of them
// exists at a time and both want the same replica count.
type Autoscaler struct {
	client         kubernetes.Interface
	syncPeriod     time.Duration
	statusManager  status.StatusManager
	triggerRunChan chan chan error
	isDegradedChan chan chan bool
	indexInformer  cache.SharedIndexInformer

	// deploymentNames are the deployments this autoscaler scales, in the calico-system
	// namespace. A deployment that does not exist is skipped.
	deploymentNames []string
	// scaleByHostEndpoints selects the count that drives scaling: host endpoints when true
	// (non-cluster-host Typha, Serval), schedulable nodes when false (in-cluster Typha).
	scaleByHostEndpoints bool

	// done is closed when the autoscaler goroutine exits, so callers can wait for shutdown.
	done chan struct{}
}

type Option func(*Autoscaler)

// OptionSyncPeriod sets a custom sync period for the autoscaler.
func OptionSyncPeriod(syncPeriod time.Duration) Option {
	return func(t *Autoscaler) {
		t.syncPeriod = syncPeriod
	}
}

// OptionScaleByHostEndpoints scales by the registered-host (HostEndpoint) count instead of
// the node count. Use it for the non-cluster-host Typha and the Serval gateway.
func OptionScaleByHostEndpoints() Option {
	return func(t *Autoscaler) {
		t.scaleByHostEndpoints = true
	}
}

// New creates a new autoscaler that scales the named deployments (in the calico-system
// namespace) to a single computed replica count, optionally applying any options. The default
// sync period is 10 seconds and, unless OptionScaleByHostEndpoints is given, scaling tracks the
// node count.
func New(cs kubernetes.Interface, indexInformer cache.SharedIndexInformer, statusManager status.StatusManager, deploymentNames []string, options ...Option) *Autoscaler {
	ta := &Autoscaler{
		client:          cs,
		statusManager:   statusManager,
		syncPeriod:      defaultSyncPeriod,
		triggerRunChan:  make(chan chan error),
		isDegradedChan:  make(chan chan bool),
		indexInformer:   indexInformer,
		deploymentNames: deploymentNames,
	}

	for _, option := range options {
		option(ta)
	}
	return ta
}

// NewHostEndpointScaler builds an autoscaler that scales the named deployments (in the
// calico-system namespace) by the registered-host (HostEndpoint) count. It creates the
// HostEndpoint informer from calicoConfig and starts it on stopCh. The caller must still call
// Start to begin scaling. Used by the non-cluster-host controller, which drives both the serval
// gateway and the legacy Typha deployment from one count.
func NewHostEndpointScaler(calicoConfig *rest.Config, clientset kubernetes.Interface, statusManager status.StatusManager, deploymentNames []string, stopCh <-chan struct{}) (*Autoscaler, error) {
	calicoClient, err := calicoclient.NewForConfig(calicoConfig)
	if err != nil {
		return nil, err
	}

	hepListWatch := cache.NewListWatchFromClient(calicoClient.ProjectcalicoV3().RESTClient(), "hostendpoints", metav1.NamespaceAll, fields.Everything())
	hepIndexInformer := cache.NewSharedIndexInformer(hepListWatch, &v3.HostEndpoint{}, 0, cache.Indexers{})
	go hepIndexInformer.Run(stopCh)

	return New(clientset, hepIndexInformer, statusManager, deploymentNames, OptionScaleByHostEndpoints()), nil
}

// Start starts the autoscaler, updating the deployment's replica count every sync period. The
// triggerRunChan can be used to trigger an auto scale run immediately, while the isDegradedChan
// can be used to get the degraded status of the last run. TriggerRun and IsDegraded should be
// used instead of accessing these channels directly.
func (t *Autoscaler) Start(ctx context.Context) {
	t.done = make(chan struct{})
	go func() {
		defer close(t.done)
		degraded := false
		ticker := time.NewTicker(t.syncPeriod)
		defer ticker.Stop()
		typhaLog.Info("Starting typha autoscaler", "deployments", t.deploymentNames, "syncPeriod", t.syncPeriod)

		// Wait for the informer to sync, bailing out if we're asked to shut down first.
		for !t.indexInformer.HasSynced() {
			select {
			case <-ctx.Done():
				typhaLog.Info("typha autoscaler shutting down")
				return
			case <-time.After(100 * time.Millisecond):
			}
		}

		// Don't autoscale or report degraded if the context has been cancelled - we're shutting down.
		if ctx.Err() != nil {
			typhaLog.Info("typha autoscaler shutting down")
			return
		}

		// Autoscale on start up then do it again every tick.
		if err := t.autoscaleReplicas(); err != nil {
			degraded = true
			typhaLog.Error(err, "Failed to autoscale typha")
			t.statusManager.SetDegraded(operator.ResourceScalingError, fmt.Sprintf("Failed to autoscale typha - %s", err.Error()), nil, typhaLog)
		}

		for {
			select {
			case <-ticker.C:
				if err := t.autoscaleReplicas(); err != nil {
					degraded = true
					typhaLog.Error(err, "Failed to autoscale typha")

					// Since this run was triggered by the ticker we need to degrade the tigera status now.
					t.statusManager.SetDegraded(operator.ResourceScalingError, fmt.Sprintf("Failed to autoscale typha - %s", err.Error()), nil, typhaLog)
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

// WaitForShutdown blocks until the autoscaler goroutine started by Start() has exited. It is a
// no-op if the autoscaler was never started. Cancel the context passed to Start() to trigger
// shutdown.
func (t *Autoscaler) WaitForShutdown() {
	if t.done != nil {
		<-t.done
	}
}

// TriggerRun triggers an autoscale run immediately and returns any error from it.
func (t *Autoscaler) TriggerRun() error {
	errChan := make(chan error)
	t.triggerRunChan <- errChan

	return <-errChan
}

// IsDegraded checks if the last autoscale run failed and returns true if it did and false otherwise.
func (t *Autoscaler) IsDegraded() bool {
	boolChan := make(chan bool)
	t.isDegradedChan <- boolChan

	return <-boolChan
}

// autoscaleReplicas calculates the number of typha pods that should be running and scales the deployment accordingly
func (t *Autoscaler) autoscaleReplicas() error {
	var expectedReplicas int
	if t.scaleByHostEndpoints {
		heps := t.getHostEndpointCounts()
		expectedReplicas = common.GetExpectedTyphaScale(heps)
	} else {
		allSchedulableNodes, linuxNodes := t.getNodeCounts()
		typhaLog.V(5).Info("Number of nodes to consider for typha autoscaling", "all", allSchedulableNodes, "linux", linuxNodes)
		expectedReplicas = common.GetExpectedTyphaScale(allSchedulableNodes)
		if linuxNodes < expectedReplicas {
			return fmt.Errorf("not enough linux nodes to schedule typha pods on, require %d and have %d", expectedReplicas, linuxNodes)
		}
	}

	typhaLog.V(5).Info("Checking if we need to scale typha", "expectedReplicas", expectedReplicas, "deployments", t.deploymentNames)
	for _, name := range t.deploymentNames {
		// A deployment that does not exist in this mode (e.g. serval while typhaEndpoint is
		// set, or vice versa) is simply skipped.
		if err := t.updateReplicas(name, int32(expectedReplicas)); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("could not scale deployment %s: %w", name, err)
		}
	}

	return nil
}

// updateReplicas updates the named deployment to the expected replicas if its current replica
// count differs.
func (t *Autoscaler) updateReplicas(name string, expectedReplicas int32) error {
	typha, err := t.client.AppsV1().Deployments(common.CalicoNamespace).Get(context.Background(), name, metav1.GetOptions{})
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

	typhaLog.Info(fmt.Sprintf("Updating %s replicas from %d to %d", name, prevReplicas, expectedReplicas))
	typha.Spec.Replicas = &expectedReplicas
	_, err = t.client.AppsV1().Deployments(common.CalicoNamespace).Update(context.Background(), typha, metav1.UpdateOptions{})
	return err
}

// getNodeCounts returns the number of all the schedulable nodes and the number of the schedulable linux nodes. The linux
// node count is needed because typha pods can only be scheduled on linux nodes, however, nodes of other os types (i.e. windows)
// still need to use typha.
func (t *Autoscaler) getNodeCounts() (int, int) {
	linuxNodes := 0
	schedulable := 0
	for _, obj := range t.indexInformer.GetIndexer().List() {
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
	return schedulable, linuxNodes
}

// getHostEndpointCounts returns the number of host endpoints in the cluster that are not created by the kube-controllers.
func (t *Autoscaler) getHostEndpointCounts() int {
	heps := 0
	for _, obj := range t.indexInformer.GetIndexer().List() {
		// Exclude auto host endpoints that are created by calico-kube-controllers.
		hep := obj.(*v3.HostEndpoint)
		if _, ok := hep.Labels[hepCreatedLabelKey]; ok && hep.Labels[hepCreatedLabelKey] == hepCreatedLabelValue {
			continue
		}

		heps++
	}
	return heps
}
