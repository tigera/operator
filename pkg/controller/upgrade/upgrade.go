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
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
)

// This package provides the utilities to upgrade a Calico manifest installation
// to an operator deployment.

const (
	defaultTyphaAutoscalerSyncPeriod = 2 * time.Minute
	nodeSelectorKey                  = "projectcalico.org/node-upgrade"
	nonOperatorNS                    = "kube-system"
	typhaDeploymentName              = "calico-typha"
	nodeDaemonSetName                = "calico-node"
)

var (
	kubeSysNodeDaemonSetNames = []string{
		nodeDaemonSetName,
	}
	kubeSysKubeControllerDeploymentNames = []string{
		"calico-kube-controllers",
	}
	kubeSysTyphaDeploymentNames = []string{
		typhaDeploymentName,
	}
	preoperatorNodeLabel = map[string]string{
		nodeSelectorKey: "pre-operator",
	}
	upgradedNodeLabel = map[string]string{
		nodeSelectorKey: "upgraded",
	}
	calicoPodLabel = map[string]string{"k8s-app": "calico-node"}
)

type CoreUpgrade struct {
	client   *kubernetes.Clientset
	informer cache.Controller
	indexer  cache.Indexer
	stopCh   chan struct{}
}

var upgrade *CoreUpgrade = nil

// IsCoreUpgradeNeeded checks if any of the old components exist that indicate we need to upgrade
// or at least still need to be removed. It returns true if any of the following exist in the
// kube-system namespace:
// calico-kube-controllers deployment, typha deployment, or calico-node deployment
func IsCoreUpgradeNeeded(cfg *rest.Config) (bool, error) {
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("Unable to get kubernetes client to check for needed upgrade: %s", err)
	}

	for _, name := range kubeSysNodeDaemonSetNames {
		_, err := c.AppsV1().DaemonSets(nonOperatorNS).Get(name, metav1.GetOptions{})
		if err == nil {
			return true, nil
		}
		if !apierrs.IsNotFound(err) {
			return false, fmt.Errorf("Failed to get daemonset %s in kube-system: %s", name, err)
		}
	}

	for _, name := range append(kubeSysKubeControllerDeploymentNames, kubeSysTyphaDeploymentNames...) {
		_, err := c.AppsV1().Deployments(nonOperatorNS).Get(name, metav1.GetOptions{})
		if err == nil {
			return true, nil
		}
		if !apierrs.IsNotFound(err) {
			return false, fmt.Errorf("Failed to get deployment %s in kube-system: %s", name, err)
		}
	}

	return false, nil
}

// GetCoreUpgrade initializes a CoreUpgrade if needed and returns a handle to it.
func GetCoreUpgrade(cfg *rest.Config) (*CoreUpgrade, error) {
	if upgrade == nil {

		upgrade = &CoreUpgrade{}
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

		for !upgrade.informer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return upgrade, nil
}

// ModifyNodeDaemonSet updates the ds DaemonSet passed in with a nodeSelector that
// the upgrade process expects to be on the Node DaemonSet that is being upgraded to.
func ModifyNodeDaemonSet(ds *appsv1.DaemonSet) {
	if ds.Spec.Template.Spec.NodeSelector == nil {
		ds.Spec.Template.Spec.NodeSelector = make(map[string]string)
	}
	for k, v := range upgradedNodeLabel {
		ds.Spec.Template.Spec.NodeSelector[k] = v
	}
}

// ModifyNodeRoleBinding updates the ClusterRoleBinding passed in to ensure the
// old node pods will continue to have the binding to the ClusterRole.
func ModifyNodeRoleBinding(crb *rbacv1.ClusterRoleBinding) {
	// The node role and binding are the same name for the manifest installation and
	// operator install, so when it is updated also include a binding
	// to the calico-node SA in kube-system.
	if crb.Subjects == nil {
		crb.Subjects = []rbacv1.Subject{}
	}
	crb.Subjects = append(crb.Subjects, rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      "calico-node",
		Namespace: nonOperatorNS,
	})
}

// ModifyTyphaDeployment updates the d Deployment pass in with a PodAntiAffinity
// to ensure the new typha pods will not be scheduled to the same nodes as the
// 'old' typha pods.
func ModifyTyphaDeployment(d *appsv1.Deployment) {
	if d.Spec.Template.Spec.Affinity == nil {
		d.Spec.Template.Spec.Affinity = &v1.Affinity{}
	}
	if d.Spec.Template.Spec.Affinity.PodAntiAffinity == nil {
		d.Spec.Template.Spec.Affinity.PodAntiAffinity = &v1.PodAntiAffinity{}
	}
	d.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution = []v1.PodAffinityTerm{
		{
			Namespaces: []string{nonOperatorNS},
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": typhaDeploymentName,
				},
			},
			TopologyKey: "kubernetes.io/hostname",
		},
	}
}

// Run will update old deployments and daemonsets, label nodes, migrate the
// calio-node pods on each node from the old pod to the new one, then clean up.
func (u *CoreUpgrade) Run(log logr.Logger, status *status.StatusManager) error {
	if err := u.deleteKubeSystemKubeControllers(); err != nil {
		setDegraded(log, status, "Failed deleting kube-system calico-kube-controllers", err.Error())
		return err
	}
	log.V(1).Info("Deleted previous calico-kube-controllers deployment")
	if err := u.waitForOperatorTyphaDeploymentReady(); err != nil {
		setDegraded(log, status, "Failed to wait for operator typha deployment to be ready", err.Error())
		return err
	}
	log.V(1).Info("Operator Typha Deployment is ready")
	if err := u.labelNonUpgradedNodes(); err != nil {
		setDegraded(log, status, "Failed to label non-upgraded nodes", err.Error())
		return err
	}
	log.V(1).Info("All non-upgraded nodes labeled")
	if err := u.ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady(); err != nil {
		setDegraded(log, status, "The kube-system node DaemonSet is not ready with the updated nodeSelect", err.Error())
		return err
	}
	log.V(1).Info("Node selector added to kube-system node DaemonSet")
	if err := u.upgradeEachNode(log); err != nil {
		setDegraded(log, status, "Failed to upgrade all nodes", err.Error())
		return err
	}
	log.V(1).Info("Nodes upgraded")
	if err := u.deleteKubeSystemCalicoNode(); err != nil {
		setDegraded(log, status, "Failed to delete kube-system node DaemonSet", err.Error())
		return err
	}
	log.V(1).Info("kube-system node DaemonSet deleted")
	if err := u.deleteKubeSystemTypha(); err != nil {
		setDegraded(log, status, "Failed to delete kube-system typha Deployment", err.Error())
		return err
	}

	return nil
}

// ShutdownUpgrade will tear down the upgrade if it was started.
func ShutdownUpgrade() {
	if upgrade != nil {
		close(upgrade.stopCh)
		upgrade = nil
	}
}

func (u *CoreUpgrade) CleanupUpgrade() error {
	if err := u.removeNodeUpgradeLabelFromNodes(); err != nil {
		return fmt.Errorf("Error cleaning up node labels: %s", err)
	}
	return nil
}

// setDegraded will log the degraded message and set degraded to the status.
func setDegraded(log logr.Logger, status *status.StatusManager, reason, msg string) {
	log.V(1).Info(reason, "error", msg)
	status.SetDegraded(reason, msg)
}

// deleteKubeSystemKubeControllers deletes the calico-kube-controllers deployment
// in the kube-system namespace
func (u *CoreUpgrade) deleteKubeSystemKubeControllers() error {
	for _, name := range kubeSysKubeControllerDeploymentNames {
		err := u.client.AppsV1().Deployments(nonOperatorNS).Delete(name, &metav1.DeleteOptions{})
		if err != nil && !apierrs.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// deleteKubeSystemTypha deletes the typha deployment
// in the kube-system namespace
func (u *CoreUpgrade) deleteKubeSystemTypha() error {
	for _, name := range kubeSysTyphaDeploymentNames {
		err := u.client.AppsV1().Deployments(nonOperatorNS).Delete(name, &metav1.DeleteOptions{})
		if err != nil && !apierrs.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// deleteKubeSystemCalicoNode deletes the calico-node daemonset
// in the kube-system namespace
func (u *CoreUpgrade) deleteKubeSystemCalicoNode() error {
	for _, name := range kubeSysNodeDaemonSetNames {
		err := u.client.AppsV1().DaemonSets(nonOperatorNS).Delete(name, &metav1.DeleteOptions{})
		if err != nil && !apierrs.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// waitForOperatorTyphaDeploymentReady waits until the 'new' typha deployment in
// the calico-system namespace is ready before continuing, it will wait up to
// 1 minute before returning with an error.
func (u *CoreUpgrade) waitForOperatorTyphaDeploymentReady() error {
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

// labelNonUpgradedNodes ensures all nodes are labeled. If they do
// not already have the upgraded value then the pre-upgrade value is set.
func (u *CoreUpgrade) labelNonUpgradedNodes() error {
	for _, obj := range u.indexer.List() {
		node, ok := obj.(*v1.Node)
		if !ok {
			return fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
		}
		if val, ok := node.Labels[nodeSelectorKey]; !ok || val != "upgraded" {
			if err := u.addNodeLabels(node.Name, preoperatorNodeLabel); err != nil {
				return err
			}
		}
	}

	return nil
}

// removeNodeUpgradeLabelFromNodes removes the label previously added to
// controll the upgrade.
func (u *CoreUpgrade) removeNodeUpgradeLabelFromNodes() error {
	for _, obj := range u.indexer.List() {
		node, ok := obj.(*v1.Node)
		if !ok {
			return fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
		}
		if err := u.removeNodeLabels(node.Name, preoperatorNodeLabel); err != nil {
			return err
		}
	}

	return nil
}

// ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady updates the calico-node DaemonSet in the
// kube-system namespace with a node selector that will prevent it from being
// deployed to nodes that have been upgraded.
func (u *CoreUpgrade) ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady() error {
	return wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		ds, err := u.client.AppsV1().DaemonSets(nonOperatorNS).Get("calico-node", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		// Check if nodeSelector is already set
		if _, ok := ds.Spec.Template.Spec.NodeSelector[nodeSelectorKey]; !ok {
			ds.Spec.Template.Spec.NodeSelector[nodeSelectorKey] = "pre-operator"

			ds, err = u.client.AppsV1().DaemonSets(nonOperatorNS).Update(ds)
			if err != nil {
				if apierrs.IsConflict(err) {
					// Retry on update conflicts.
					return false, nil
				}
				return false, err
			}
		}

		if ds.Status.DesiredNumberScheduled != ds.Status.NumberReady {
			return false, fmt.Errorf("All pods are not ready yet: %d/%d", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
		}

		// Successful update
		return true, nil
	})
}

// upgradeEachNode ensures that the calico-node pods are ready and then update
// the label on one node at a time, ensuring pod becomes ready before starting
// the cycle again. Once the nodes are updated we will get the list of nodes
// that need to be upgraded in case there were more added.
func (u *CoreUpgrade) upgradeEachNode(log logr.Logger) error {
	nodes := u.getNodesToUpgrade()
	for len(nodes) > 0 {
		log.WithValues("count", len(nodes)).V(1).Info("nodes to upgrade")
		for _, node := range nodes {
			// This is to ensure that our new pods are becoming healthy before continuing on.
			// We only wait up to 2 minutes after switching a node to allow the new pod
			// to come up. Also if the operator crashed we don't want to continue continue
			// updating if the pods are not healthy.
			log.V(1).Info("Waiting for new calico pods to be healthy")
			err := u.waitForCalicoPodsHealthy()
			if err == nil {
				log.WithValues("node.Name", node.Name).V(1).Info("Adding label to node")
				err = u.addNodeLabels(node.Name, upgradedNodeLabel)
				if err != nil {
					return fmt.Errorf("Setting label on node %s failed; %s", node.Name, err)
				}
				log.V(1).Info("Waiting for new calico pod to start and be healthy")
				u.waitCalicoPodReadyForNode(node.Name, 1*time.Second, 2*time.Minute, calicoPodLabel)
			} else {
				log.WithValues("error", err).V(1).Info("Error checking for new healthy pods")
				time.Sleep(10 * time.Second)
			}
		}
		// Fetch any new nodes that have been added during upgrade.
		nodes = u.getNodesToUpgrade()
	}
	return nil
}

// getNodesToUpgrade returns a list of all nodes that need to be upgraded.
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

func (u *CoreUpgrade) waitForCalicoPodsHealthy() error {
	return wait.PollImmediate(5*time.Second, 1*time.Minute, func() (bool, error) {
		ksD, ksR, err := u.getNumPodsDesiredAndReady(nonOperatorNS, nodeDaemonSetName)
		if err != nil {
			return false, err
		}
		csD, csR, err := u.getNumPodsDesiredAndReady(common.CalicoNamespace, nodeDaemonSetName)
		if err != nil {
			return false, err
		}

		// TODO: When we support configuring adjusting the rolling update unavailable,
		// we should use that configuration here.
		if (ksD + csD) == (ksR + csR) {
			// no update needed
			return true, nil

		}

		// Retry on update conflicts.
		return false, nil
	})
}

func (u *CoreUpgrade) getNumPodsDesiredAndReady(namespace, daemonset string) (int32, int32, error) {
	ds, err := u.client.AppsV1().DaemonSets(namespace).Get(daemonset, metav1.GetOptions{})
	if err != nil {
		return 0, 0, err
	}

	return ds.Status.DesiredNumberScheduled, ds.Status.NumberReady, nil
}

// addNodeLabels adds the specified labels to the named node. Perform
// Get/Check/Update so that it always working on latest version.
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

// waitCalicoPodReadyForNode waits for the calico-node pod in the calico-system
// namespace to become ready on a node.
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

// isPodRunningAndReady returns true if the passed in pod is ready.
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
