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

package migration

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

// This package provides the utilities to migrate from a Calico manifest installation
// to an operator deployment.

const (
	// Label key set on nodes to indicate their migration status.
	nodeSelectorKey = "projectcalico.org/operator-node-migration"
	// Value used for the node selector for 'unmigrated' nodes
	nodeSelectorValuePre = "pre-operator"
	// Value used for the node selector for migrated nodes
	nodeSelectorValuePost = "migrated"
	// Kube system namespace name
	kubeSystem                   = "kube-system"
	typhaDeploymentName          = "calico-typha"
	nodeDaemonSetName            = "calico-node"
	kubeControllerDeploymentName = "calico-kube-controllers"
)

var (
	preOperatorNodeLabel = map[string]string{nodeSelectorKey: nodeSelectorValuePre}
	migratedNodeLabel    = map[string]string{nodeSelectorKey: nodeSelectorValuePost}
	calicoPodLabel       = map[string]string{"k8s-app": "calico-node"}
)

type CoreNamespaceMigration struct {
	client            *kubernetes.Clientset
	informer          cache.Controller
	indexer           cache.Indexer
	stopCh            chan struct{}
	migrationComplete bool
}

// NeedsCoreNamespaceMigration returns true if any components still exist in
// the kube-system namespace.
// It checks the following in the kube-system namespace:
// calico-kube-controllers deployment, typha deployment, or calico-node deployment
func (m *CoreNamespaceMigration) NeedsCoreNamespaceMigration() (bool, error) {
	if m.migrationComplete == true {
		return false, nil
	}

	_, err := m.client.AppsV1().DaemonSets(kubeSystem).Get(nodeDaemonSetName, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if !apierrs.IsNotFound(err) {
		return false, fmt.Errorf("Failed to get daemonset %s in kube-system: %s", nodeDaemonSetName, err)
	}

	_, err = m.client.AppsV1().Deployments(kubeSystem).Get(kubeControllerDeploymentName, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if !apierrs.IsNotFound(err) {
		return false, fmt.Errorf("Failed to get deployment %s in kube-system: %s", kubeControllerDeploymentName, err)
	}

	_, err = m.client.AppsV1().Deployments(kubeSystem).Get(typhaDeploymentName, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if !apierrs.IsNotFound(err) {
		return false, fmt.Errorf("Failed to get deployment %s in kube-system: %s", typhaDeploymentName, err)
	}

	return false, nil
}

// NewCoreNamespaceMigration initializes a CoreNamespaceMigration and returns a handle to it.
func NewCoreNamespaceMigration(cfg *rest.Config) (*CoreNamespaceMigration, error) {
	migration := &CoreNamespaceMigration{migrationComplete: false}
	var err error
	migration.client, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("Unable to get kubernetes client: %s", err)
	}

	// Create a Node watcher.
	listWatcher := cache.NewListWatchFromClient(migration.client.CoreV1().RESTClient(), "nodes", "", fields.Everything())

	// Setup event handlers
	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {},
	}

	// Informer handles managing the watch and signals us when nodes are added.
	migration.indexer, migration.informer = cache.NewIndexerInformer(listWatcher, &v1.Node{}, 0, handlers, cache.Indexers{})

	migration.stopCh = make(chan struct{})

	go migration.informer.Run(migration.stopCh)

	for !migration.informer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}

	return migration, nil
}

// LimitDaemonSetToMigratedNodes updates the ds DaemonSet passed in with a
// nodeSelector that will only allow pods to be schedueled on nodes with
// the key:value projectcalico.org/operator-node-migration:migrated.
// This is to ensure that only one kube-system calico-node or the new calico-node
// pod will attempt to run on one node at a time.
func LimitDaemonSetToMigratedNodes(ds *appsv1.DaemonSet) {
	if ds.Spec.Template.Spec.NodeSelector == nil {
		ds.Spec.Template.Spec.NodeSelector = make(map[string]string)
	}
	for k, v := range migratedNodeLabel {
		ds.Spec.Template.Spec.NodeSelector[k] = v
	}
}

// AddBindingForKubeSystemNode updates the ClusterRoleBinding passed in
// to also bind the service account in the kube-system namespace to the
// Role. Without this, when the new ClusterRoleBinding overwrites the
// previous role binding the kube-system calico-node account would lose
// permissions for accessing the datastore.
func AddBindingForKubeSystemNode(crb *rbacv1.ClusterRoleBinding) {
	// The node role and binding are the same name for the manifest installation and
	// operator install, so when it is updated also include a binding
	// to the calico-node SA in kube-system.
	if crb.Subjects == nil {
		crb.Subjects = []rbacv1.Subject{}
	}
	crb.Subjects = append(crb.Subjects, rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      "calico-node",
		Namespace: kubeSystem,
	})
}

// SetTyphaAntiAffinity updates the Deployment passed in with a PodAntiAffinity
// to ensure the new typha pods will not be scheduled to the same nodes as the
// 'old' typha pods.
func SetTyphaAntiAffinity(d *appsv1.Deployment) {
	if d.Spec.Template.Spec.Affinity == nil {
		d.Spec.Template.Spec.Affinity = &v1.Affinity{}
	}
	if d.Spec.Template.Spec.Affinity.PodAntiAffinity == nil {
		d.Spec.Template.Spec.Affinity.PodAntiAffinity = &v1.PodAntiAffinity{}
	}
	d.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution = []v1.PodAffinityTerm{
		{
			Namespaces: []string{kubeSystem},
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
func (m *CoreNamespaceMigration) Run(log logr.Logger, status *status.StatusManager) error {
	if err := m.deleteKubeSystemKubeControllers(); err != nil {
		setDegraded(log, status, "Failed deleting kube-system calico-kube-controllers", err.Error())
		return err
	}
	log.V(1).Info("Deleted previous calico-kube-controllers deployment")
	if err := m.waitForOperatorTyphaDeploymentReady(); err != nil {
		setDegraded(log, status, "Failed to wait for operator typha deployment to be ready", err.Error())
		return err
	}
	log.V(1).Info("Operator Typha Deployment is ready")
	if err := m.labelUnmigratedNodes(); err != nil {
		setDegraded(log, status, "Failed to label unmigrated nodes", err.Error())
		return err
	}
	log.V(1).Info("All unmigrated nodes labeled")
	if err := m.ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady(); err != nil {
		setDegraded(log, status, "The kube-system node DaemonSet is not ready with the updated nodeSelect", err.Error())
		return err
	}
	log.V(1).Info("Node selector added to kube-system node DaemonSet")
	if err := m.migrateEachNode(log); err != nil {
		setDegraded(log, status, "Failed to migrate all nodes", err.Error())
		return err
	}
	log.V(1).Info("Nodes migrated")
	if err := m.deleteKubeSystemCalicoNode(); err != nil {
		setDegraded(log, status, "Failed to delete kube-system node DaemonSet", err.Error())
		return err
	}
	log.V(1).Info("kube-system node DaemonSet deleted")
	if err := m.deleteKubeSystemTypha(); err != nil {
		setDegraded(log, status, "Failed to delete kube-system typha Deployment", err.Error())
		return err
	}

	return nil
}

// NeedCleanup returns if the migration has been marked completed or not.
// If cleanup is needed then we need to make sure that all our labels have
// been removed from the nodes, we could check if the label is present
// on any nodes but it is almost the same operator to call the remove
// so we'll assume there are labels if we have not removed them previously.
func (m *CoreNamespaceMigration) NeedCleanup() bool {
	return !m.migrationComplete
}

// CleanupMigration ensures all labels used during the migration are removed
// and any migration resources are stopped.
func (m *CoreNamespaceMigration) CleanupMigration() error {
	if m.migrationComplete {
		return nil
	}
	if err := m.removeNodeMigrationLabelFromNodes(); err != nil {
		return fmt.Errorf("Error cleaning up node labels: %s", err)
	}

	close(m.stopCh)

	m.migrationComplete = true
	return nil
}

// setDegraded will log the degraded message and set degraded to the status.
func setDegraded(log logr.Logger, status *status.StatusManager, reason, msg string) {
	log.V(1).Info(reason, "error", msg)
	status.SetDegraded(reason, msg)
}

// deleteKubeSystemKubeControllers deletes the calico-kube-controllers deployment
// in the kube-system namespace
func (m *CoreNamespaceMigration) deleteKubeSystemKubeControllers() error {
	err := m.client.AppsV1().Deployments(kubeSystem).Delete(kubeControllerDeploymentName, &metav1.DeleteOptions{})
	if err != nil && !apierrs.IsNotFound(err) {
		return err
	}
	return nil
}

// deleteKubeSystemTypha deletes the typha deployment
// in the kube-system namespace
func (m *CoreNamespaceMigration) deleteKubeSystemTypha() error {
	err := m.client.AppsV1().Deployments(kubeSystem).Delete(typhaDeploymentName, &metav1.DeleteOptions{})
	if err != nil && !apierrs.IsNotFound(err) {
		return err
	}
	return nil
}

// deleteKubeSystemCalicoNode deletes the calico-node daemonset
// in the kube-system namespace
func (m *CoreNamespaceMigration) deleteKubeSystemCalicoNode() error {
	err := m.client.AppsV1().DaemonSets(kubeSystem).Delete(nodeDaemonSetName, &metav1.DeleteOptions{})
	if err != nil && !apierrs.IsNotFound(err) {
		return err
	}
	return nil
}

// waitForOperatorTyphaDeploymentReady waits until the 'new' typha deployment in
// the calico-system namespace is ready before continuing, it will wait up to
// 1 minute before returning with an error.
func (m *CoreNamespaceMigration) waitForOperatorTyphaDeploymentReady() error {
	return wait.PollImmediate(1*time.Second, 5*time.Minute, func() (bool, error) {
		d, err := m.client.AppsV1().Deployments(common.CalicoNamespace).Get(common.TyphaDeploymentName, metav1.GetOptions{})
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

// labelUnmigratedNodes ensures all nodes are labeled. If they do
// not already have the migrated value then the pre-migrated value is set.
func (m *CoreNamespaceMigration) labelUnmigratedNodes() error {
	for _, obj := range m.indexer.List() {
		node, ok := obj.(*v1.Node)
		if !ok {
			return fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
		}
		if val, ok := node.Labels[nodeSelectorKey]; !ok || val != nodeSelectorValuePost {
			if err := m.addNodeLabels(node.Name, preOperatorNodeLabel); err != nil {
				return err
			}
		}
	}

	return nil
}

// removeNodeMigrationLabelFromNodes removes the label previously added to
// control the migration.
func (m *CoreNamespaceMigration) removeNodeMigrationLabelFromNodes() error {
	for _, obj := range m.indexer.List() {
		node, ok := obj.(*v1.Node)
		if !ok {
			return fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
		}
		if err := m.removeNodeLabels(node.Name, preOperatorNodeLabel); err != nil {
			return err
		}
	}

	return nil
}

// ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady updates the calico-node DaemonSet in the
// kube-system namespace with a node selector that will prevent it from being
// deployed to nodes that have been migrated and waits for the daemonset to update.
func (m *CoreNamespaceMigration) ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady() error {
	return wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		ds, err := m.client.AppsV1().DaemonSets(kubeSystem).Get("calico-node", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		// Check if nodeSelector is already set
		if _, ok := ds.Spec.Template.Spec.NodeSelector[nodeSelectorKey]; !ok {
			ds.Spec.Template.Spec.NodeSelector[nodeSelectorKey] = nodeSelectorValuePre

			ds, err = m.client.AppsV1().DaemonSets(kubeSystem).Update(ds)
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

// migrateEachNode ensures that the calico-node pods are ready and then update
// the label on one node at a time, ensuring pod becomes ready before starting
// the cycle again. Once the nodes are updated we will get the list of nodes
// that need to be migrated in case there were more added.
func (m *CoreNamespaceMigration) migrateEachNode(log logr.Logger) error {
	nodes := m.getNodesToMigrate()
	for len(nodes) > 0 {
		log.WithValues("count", len(nodes)).V(1).Info("nodes to migrate")
		for _, node := range nodes {
			// This is to ensure that our new pods are becoming healthy before continuing on.
			// We only wait up to 2 minutes after switching a node to allow the new pod
			// to come up. Also if the operator crashed we don't want to continue
			// updating if the pods are not healthy.
			log.V(1).Info("Waiting for new calico pods to be healthy")
			err := m.waitForCalicoPodsHealthy()
			if err == nil {
				log.WithValues("node.Name", node.Name).V(1).Info("Adding label to node")
				err = m.addNodeLabels(node.Name, migratedNodeLabel)
				if err != nil {
					return fmt.Errorf("Setting label on node %s failed; %s", node.Name, err)
				}
				log.V(1).Info("Waiting for new calico pod to start and be healthy")
				m.waitCalicoPodReadyForNode(node.Name, 1*time.Second, 2*time.Minute, calicoPodLabel)
			} else {
				log.WithValues("error", err).V(1).Info("Error checking for new healthy pods")
				time.Sleep(10 * time.Second)
			}
		}
		// Fetch any new nodes that have been added during migration.
		nodes = m.getNodesToMigrate()
	}
	return nil
}

// getNodesToMigrate returns a list of all nodes that need to be migrated.
func (m *CoreNamespaceMigration) getNodesToMigrate() []*v1.Node {
	nodes := []*v1.Node{}
	for _, obj := range m.indexer.List() {
		node := obj.(*v1.Node)
		if val, ok := node.Labels[nodeSelectorKey]; !ok || val != nodeSelectorValuePost {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// waitForCalicoPodsHealthy waits for all calico pods to be healthy. If all pods
// are not ready then an error is returned.
// The function checks both the daemonset in kube-system and the calico-system
// to see if the number of desired pods matches the number of ready pods.
// We want this to ensure we are only updating one pod at a time like a regular
// kubernetes rolling update.
func (m *CoreNamespaceMigration) waitForCalicoPodsHealthy() error {
	return wait.PollImmediate(5*time.Second, 1*time.Minute, func() (bool, error) {
		ksD, ksR, err := m.getNumPodsDesiredAndReady(kubeSystem, nodeDaemonSetName)
		if err != nil {
			return false, err
		}
		csD, csR, err := m.getNumPodsDesiredAndReady(common.CalicoNamespace, nodeDaemonSetName)
		if err != nil {
			return false, err
		}

		// TODO: When we support configuring adjusting the rolling update unavailable,
		// we should use that configuration here.
		if ksD == ksR && csD == csR {
			// Desired pods are ready
			return true, nil

		}

		// Wait for counts to equal
		return false, nil
	})
}

func (m *CoreNamespaceMigration) getNumPodsDesiredAndReady(namespace, daemonset string) (int32, int32, error) {
	ds, err := m.client.AppsV1().DaemonSets(namespace).Get(daemonset, metav1.GetOptions{})
	if err != nil {
		return 0, 0, err
	}

	return ds.Status.DesiredNumberScheduled, ds.Status.NumberReady, nil
}

// addNodeLabels adds the specified labels to the named node. Perform
// Get/Check/Update so that it always working on latest version.
// If node labels has been set already, do nothing.
func (m *CoreNamespaceMigration) addNodeLabels(nodeName string, labelMaps ...map[string]string) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := m.client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
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
			_, err := m.client.CoreV1().Nodes().Update(node)
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

// Remove node labels from node. Perform Get/Check/Update so that it always working on the
// most recent version of the resource.
// If node labels do not exist, do nothing.
func (m *CoreNamespaceMigration) removeNodeLabels(nodeName string, labelMaps ...map[string]string) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := m.client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
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
			_, err := m.client.CoreV1().Nodes().Update(node)
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
func (m *CoreNamespaceMigration) waitCalicoPodReadyForNode(nodeName string, interval, timeout time.Duration, label map[string]string) error {
	return wait.PollImmediate(interval, timeout, func() (bool, error) {
		podList, err := m.client.CoreV1().Pods(common.CalicoNamespace).List(
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
