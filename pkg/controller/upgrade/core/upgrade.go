// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package upgrade

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
)

// This package provides the utilities to upgrade a Calico manifest installation
// to an operator deployment.

const (
	defaultTyphaAutoscalerSyncPeriod = 2 * time.Minute
	nodeSelectorKey                  = "projectcalico.org/node-upgrade"
	oldNs                            = "kube-system"
	typhaDeploymentName              = "calico-typha"
	nodeDaemonSetName                = "calico-node"
)

var (
	kubeSysNodeDaemonSetNames = map[string]bool{
		nodeDaemonSetName: true,
	}
	kubeSysKubeControllerDeploymentNames = map[string]bool{
		"calico-kube-controllers": true,
	}
	kubeSysTyphaDeploymentNames = map[string]bool{
		typhaDeploymentName: true,
	}
	oldNodeLabel = map[string]string{
		nodeSelectorKey: "pre-operator",
	}
	newNodeLabel = map[string]string{
		nodeSelectorKey: "upgraded",
	}
	calicoPodLabel = map[string]string{"k8s-app": "calico-node"}
)

type CoreUpgrade struct {
	client   *kubernetes.Clientset
	informer cache.Controller
	indexer  cache.Indexer
	stopCh   chan struct{}
	//latestProgress   int
	//highestProgress  int
	//statusConditions map[StatusConditionType]*operatorv1.TigeraStatusCondition
	lock      sync.Mutex
	nodeCount int
}

var upgrade *CoreUpgrade = nil

func IsCoreUpgradeNeeded(cfg *rest.Config) (bool, error) {
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("Unable to get kubernetes client to check for needed upgrade: %s", err)
	}

	dsl, err := c.AppsV1().DaemonSets("kube-system").List(metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("Unable to list daemonsets in kube-system: %s", err)
	}
	for _, ds := range dsl.Items {
		_, ok := kubeSysNodeDaemonSetNames[ds.Name]
		if ok {
			return true, nil
		}
	}

	dl, err := c.AppsV1().Deployments("kube-system").List(metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("Unable to list deployments in kube-system: %s", err)
	}
	for _, ds := range dl.Items {
		_, ok := kubeSysKubeControllerDeploymentNames[ds.Name]
		if ok {
			return true, nil
		}
		_, ok = kubeSysTyphaDeploymentNames[ds.Name]
		if ok {
			return true, nil
		}
	}

	return false, nil
}

func AddInstallationUpgradeWatches(c *controller.Controller) error {
	//c.Watch(&source.Kind{Type: &
	//TODO:
	return nil
}

func GetCoreUpgrade(cfg *rest.Config) (*CoreUpgrade, error) {
	if upgrade == nil {

		upgrade = &CoreUpgrade{
			//latestProgress:  0,
			//highestProgress: 0,
			//statusConditions: map[StatusConditionType]*operatorv1.TigeraStatusCondition{
			//	operatorv1.ComponentAvailable: &operatorv1.TigeraStatusCondition{
			//		Type:   operatorv1.ComponentAvailable,
			//		Status: operatorv1.ConditionUnknown,
			//	},
			//	operatorv1.ComponentProgressing: &operatorv1.TigeraStatusCondition{
			//		Type:   operatorv1.ComponentProgressing,
			//		Status: operatorv1.ConditionUnknown,
			//	},
			//	operatorv1.ComponentDegraded: &operatorv1.TigeraStatusCondition{
			//		Type:   operatorv1.ComponentDegraded,
			//		Status: operatorv1.ConditionUnknown,
			//	},
			//},
			nodeCount: 10,
		}
		var err error
		upgrade.client, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("Unable to get kubernetes client for Core Upgrade: %s", err)
		}

		// Create a Node watcher.
		listWatcher := cache.NewListWatchFromClient(upgrade.client.CoreV1().RESTClient(), "nodes", "", fields.Everything())

		// Setup event handlers
		handlers := cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {},
		}

		// Informer handles managing the watch and signals us when nodes are added.
		upgrade.indexer, upgrade.informer = cache.NewIndexerInformer(listWatcher, &v1.Node{}, 0, handlers, cache.Indexers{})

		upgrade.stopCh = make(chan struct{})

		go upgrade.informer.Run(upgrade.stopCh)
	}

	return upgrade, nil
}

func ModifyNodeDaemonSet(ds *appsv1.DaemonSet) {
	newNodeLabel = map[string]string{
		nodeSelectorKey: "upgraded",
	}
	if ds.Spec.Template.Spec.NodeSelector == nil {
		ds.Spec.Template.Spec.NodeSelector = make(map[string]string)
	}
	for k, v := range newNodeLabel {
		ds.Spec.Template.Spec.NodeSelector[k] = v
	}
}

func ModifyTyphaDeployment(d *appsv1.Deployment) {
	if d.Spec.Template.Spec.Affinity == nil {
		d.Spec.Template.Spec.Affinity = &v1.Affinity{}
	}
	if d.Spec.Template.Spec.Affinity.PodAntiAffinity == nil {
		d.Spec.Template.Spec.Affinity.PodAntiAffinity = &v1.PodAntiAffinity{}
	}
	d.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution = []v1.PodAffinityTerm{
		{
			Namespaces: []string{"kube-system"},
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": typhaDeploymentName,
				},
			},
			TopologyKey: "kubernetes.io/hostname",
		},
	}
}

func RequeueDelay(log logr.Logger) time.Duration {
	if upgrade == nil {
		log.V(1).Info("No upgrade available to get requeue delay")
		return time.Second
	}
	upgrade.lock.Lock()
	defer upgrade.lock.Unlock()
	return time.Duration(upgrade.nodeCount*2) * time.Second
}

func (u *CoreUpgrade) Run(log logr.Logger, status *status.StatusManager) error {
	if u.stopCh == nil {
		return nil
	}
	if err := u.deleteKubeSystemKubeControllers(); err != nil {
		setDegraded(log, status, "Failed deleting old calico-kube-controllers", err.Error())
		return err
	}
	log.V(1).Info("Deleted previous calico-kube-controllers deployment")
	if err := u.waitForNewTyphaDeploymentReady(); err != nil {
		setDegraded(log, status, "Failed to wait for new typha deployment to be ready", err.Error())
		return err
	}
	log.V(1).Info("New Typha Deployment is ready")
	for !u.informer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}
	log.V(1).Info("Node informer is synced")
	if err := u.labelNonUpgradedNodesForOldNode(); err != nil {
		setDegraded(log, status, "Failed to label non-upgraded nodes", err.Error())
		return err
	}
	log.V(1).Info("All non-upgraded nodes labeled for old node DaemonSet")
	if err := u.addNodeSelectorToOldNodeDaemonSet(); err != nil {
		setDegraded(log, status, "Failed to add nodeSelector to old node DaemonSet", err.Error())
		return err
	}
	log.V(1).Info("Node selector added to old node DaemonSet")
	if err := u.upgradeEachNode(); err != nil {
		setDegraded(log, status, "Failed to upgrade all nodes", err.Error())
		return err
	}
	log.V(1).Info("Nodes upgraded")

	// TODO: Delete old node DaemonSet
	// TODO: Delete old typha

	close(u.stopCh)
	return nil
}

func setDegraded(log logr.Logger, status *status.StatusManager, reason, msg string) {
	log.V(1).Info(reason, "error", msg)
	status.SetDegraded(reason, msg)
}

//func (u *CoreUpgrade) advanceProgress() {
//	u.latestProgress++
//	if u.latestProgress > u.highestProgress {
//		u.highestProgress = u.latestProgress
//	}
//}
//
//func (u *CoreUpgrade) setProgress(msg string) {
//	if u.latestProgress < u.highestProgress {
//		return
//	}
//	st := u.statusConditions[operatorv1.ComponentProgressing]
//	if st.Status != operatorv1.ConditionTrue || st.Reason != msg {
//		st.Status = operatorv1.ConditionTrue
//		st.Reason = msg
//		st.LastTransitionTime = metav1.NewTime(time.Now())
//	}
//	st = u.statusConditions[operatorv1.ComponentDegraded]
//	if st.Status != operatorv1.ConditionFalse {
//		st.Status = operatorv1.ConditionFalse
//		st.LastTransitionTime = metav1.NewTime(time.Now())
//	}
//}
//
//func (u *CoreUpgrade) setDegraded(reason, msg string) {
//}

func (u *CoreUpgrade) deleteKubeSystemKubeControllers() error {
	dsl, err := u.client.AppsV1().Deployments("kube-system").List(metav1.ListOptions{})
	if err != nil {
		if apierrs.IsNotFound(err) {
			return nil
		}
		return err
	}
	for _, ds := range dsl.Items {
		_, ok := kubeSysKubeControllerDeploymentNames[ds.Name]
		if ok {
			return u.client.AppsV1().Deployments("kube-system").Delete(ds.Name, &metav1.DeleteOptions{})
		}
	}

	return nil
}

func (u *CoreUpgrade) waitForNewTyphaDeploymentReady() error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		d, err := u.client.AppsV1().Deployments(common.CalicoNamespace).Get(common.TyphaDeploymentName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if d.Status.AvailableReplicas == d.Status.Replicas {
			// Expected replicas active
			return true, nil
		}
		return false,
			fmt.Errorf("Waiting for typha to have %d replicas, currently at %d",
				d.Status.Replicas, d.Status.AvailableReplicas)
	})
}

func (u *CoreUpgrade) labelNonUpgradedNodesForOldNode() error {
	for _, obj := range u.indexer.List() {
		node, ok := obj.(*v1.Node)
		if !ok {
			return fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
		}
		if val, ok := node.Labels[nodeSelectorKey]; !ok || val != "upgraded" {
			if err := u.addNodeLabels(node.Name, oldNodeLabel); err != nil {
				return err
			}
		}
	}

	return nil
}

func (u *CoreUpgrade) addNodeSelectorToOldNodeDaemonSet() error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		ds, err := u.client.AppsV1().DaemonSets("kube-system").Get("calico-node", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		// Check if nodeSelector is already set
		if _, ok := ds.Spec.Template.Spec.NodeSelector[nodeSelectorKey]; ok {
			// no update needed
			return true, nil
		}

		ds.Spec.Template.Spec.NodeSelector[nodeSelectorKey] = "pre-operator"

		_, err = u.client.AppsV1().DaemonSets("kube-system").Update(ds)
		if err == nil {
			// Successful update
			return true, nil
		}
		if !apierrs.IsConflict(err) {
			return false, err
		}

		// Retry on update conflicts.
		return false, nil
	})
}

func (u *CoreUpgrade) upgradeEachNode() error {
	nodes := u.getNodesToUpgrade()
	for len(nodes) > 0 {
		for _, node := range nodes {
			err := u.waitForNewCalicoPodsHealthy()
			if err != nil {
				err = u.addNodeLabels(node.Name, newNodeLabel)
				if err != nil {
					return fmt.Errorf("Setting label on node %s failed; %s", node.Name, err)
				}
				u.waitCalicoPodReadyForNode(node.Name, 1*time.Second, 2*time.Minute, calicoPodLabel)
			}
		}
		// Fetch any new nodes that have been added during upgrade.
		nodes = u.getNodesToUpgrade()
	}
	return nil
}

func (u *CoreUpgrade) getNodesToUpgrade() []*v1.Node {
	nodes := []*v1.Node{}
	for _, obj := range u.indexer.List() {
		node := obj.(*v1.Node)
		if val, ok := node.Labels[nodeSelectorKey]; !ok || val != "upgraded" {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func (u *CoreUpgrade) waitForNewCalicoPodsHealthy() error {
	w, err := u.client.AppsV1().DaemonSets(common.CalicoNamespace).Watch(metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer w.Stop()
	for e := range w.ResultChan() {
		switch e.Type {
		case watch.Deleted:
			return fmt.Errorf("While waiting for calico-node pods to become healthy the DaemonSet was deleted")
		case watch.Error:
			return fmt.Errorf("Error while waiting for calico-node pods to become healthy: %s", e.Object)
		}

		ds := e.Object.(*appsv1.DaemonSet)
		if ds.Name == common.NodeDaemonSetName {
			if ds.Status.NumberReady == ds.Status.DesiredNumberScheduled {
				return nil
			}
		}

	}
	return fmt.Errorf("Reading result while waiting for pod health was unexpected")
}

// Add node labels to node. Perform Get/Check/Update so that it always working on latest version.
// If node labels has been set already, do nothing.
func (u *CoreUpgrade) addNodeLabels(nodeName string, labelMaps ...map[string]string) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := u.client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := false
		for _, labels := range labelMaps {
			for k, v := range labels {
				if currentVal, ok := node.Labels[k]; ok && currentVal == v {
					continue
				}
				node.Labels[k] = v
				needUpdate = true
			}
		}

		if needUpdate {
			_, err := u.client.CoreV1().Nodes().Update(node)
			if err == nil {
				return true, nil
			}
			if !apierrs.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

// Remove node labels to node. Perform Get/Check/Update so that it always working on latest version.
// If node labels do not exist, do nothing.
func (u *CoreUpgrade) removeNodeLabels(nodeName string, labelMaps ...map[string]string) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := u.client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := false
		for _, labels := range labelMaps {
			for k := range labels {
				if _, ok := node.Labels[k]; ok {
					delete(node.Labels, k)
					needUpdate = true
				}
			}
		}

		if needUpdate {
			_, err := u.client.CoreV1().Nodes().Update(node)
			if err == nil {
				return true, nil
			}
			if !apierrs.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

// Wait for a pod becoming ready on a node.
func (u *CoreUpgrade) waitCalicoPodReadyForNode(nodeName string, interval, timeout time.Duration, label map[string]string) error {
	return wait.PollImmediate(interval, timeout, func() (bool, error) {
		podList, err := u.client.CoreV1().Pods(common.CalicoNamespace).List(
			metav1.ListOptions{
				FieldSelector: fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName}).String(),
				LabelSelector: labels.SelectorFromSet(label).String(),
			},
		)
		if err != nil {
			// Something wrong, stop waiting
			return true, err
		}

		if len(podList.Items) == 0 {
			// No pod yet, retry
			return false, nil
		}

		if len(podList.Items) > 1 {
			// Multiple pods, stop waiting
			return true, fmt.Errorf("Getting multiple pod with label %v on node %s", label, nodeName)
		}

		pod := podList.Items[0]
		if isPodRunningAndReady(pod) {
			// Pod running and ready, stop waiting
			return true, nil
		}

		// Pod not ready yet, retry
		return false, nil
	})
}

func isPodRunningAndReady(pod v1.Pod) bool {
	if pod.Status.Phase != v1.PodRunning {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == v1.PodReady && c.Status == v1.ConditionTrue {
			return true
		}
	}

	return false
}
