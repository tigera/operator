package status

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var log = logf.Log.WithName("status_manager")

// StatusManager manages the status for a single controller and component, and reports the status via
// a TigeraStatus API object. The status manager uses the following conditions/states to represent the
// component's current status:
//
// - Available: The component is successfully running. All pods launched by the component are healthy.
//              An upgrade may or may not be occuring.
// - Progressing: A state change is occuring. It may be that the component is being installed for the
//                first time, or being upgraded to a new configuration or version.
// - Degraded: The component is not running the desired state and is not progressing towards it. Either the
//             component has not been installed, has been updated with invalid configuration, or has crashed.
//
// Each of these states can be set independently of each other. For example, a component can be both available and
// degraded if it is running successfully but a configuration change has resulted in a configuration that cannot
// be actioned.
type StatusManager struct {
	client      client.Client
	component   string
	daemonsets  []types.NamespacedName
	deployments []types.NamespacedName
	lock        sync.Mutex
	available   bool
	enabled     bool

	// Track degraded state as set by external controllers.
	degraded               bool
	explicitDegradedMsg    string
	explicitDegradedReason string

	// Keep track of currently calculated status.
	progressing []string
	failing     []string
}

func New(client client.Client, component string) *StatusManager {
	return &StatusManager{
		client:      client,
		component:   component,
		daemonsets:  []types.NamespacedName{},
		deployments: []types.NamespacedName{},
	}
}

// Run starts the status manager state monitoring routine.
func (m *StatusManager) Run() {
	go func() {
		// Loop forever, periodically checking dependent objects for their state.
		for {
			if !m.syncState() {
				// Waiting to be in sync.
				time.Sleep(5 * time.Second)
				continue
			}

			// We've collected knowledge about the current state of the objects we're monitoring.
			// Now, use that to update the TigeraStatus object for this manager.
			if m.IsAvailable() {
				m.setAvailable("All objects available", "")
			} else {
				m.clearAvailable()
			}

			if m.IsProgressing() {
				m.setProgressing("Not all pods are ready", m.progressingMessage())
			} else {
				m.clearProgressing()
			}

			if m.IsDegraded() {
				m.setDegraded(m.degradedReason(), m.degradedMessage())
			} else {
				m.clearDegraded()
			}

			time.Sleep(5 * time.Second)
		}
	}()
}

// Enable indicates to the status manager that it should start reporting status. Until Enable is called,
// the status manager will be be in a "dormant" state, and will not write status to the API.
// Call this function from a controller once it has first received an instance of its CRD.
func (m *StatusManager) Enable() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.enabled = true
}

// SetDaemonsets tells the status manager to monitor the health of the given daemonsets.
func (m *StatusManager) SetDaemonsets(ds []types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.daemonsets = ds
}

// SetDeployments tells the status manager to monitor the health of the given deployments.
func (m *StatusManager) SetDeployments(deps []types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.deployments = deps
}

// SetDegraded sets degraded state with the provided reason and message.
func (m *StatusManager) SetDegraded(reason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.degraded = true
	m.explicitDegradedReason = reason
	m.explicitDegradedMsg = msg
}

// ClearDegraded clears degraded state.
func (m *StatusManager) ClearDegraded() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.degraded = false
	m.explicitDegradedReason = ""
	m.explicitDegradedMsg = ""
}

// IsAvailable returns true if the component is available and false otherwise.
func (m *StatusManager) IsAvailable() bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.progressing == nil || m.failing == nil {
		// We haven't learned our state yet. Return false.
		return false
	}
	return len(m.failing) == 0 && len(m.progressing) == 0
}

// IsProgressing returns true if the component is progressing and false otherwise.
func (m *StatusManager) IsProgressing() bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.progressing == nil || m.failing == nil {
		// We haven't learned our state yet. Return false.
		return false
	}
	return len(m.progressing) != 0 && len(m.failing) == 0
}

// IsDegraded returns true if the component is degraded and false otherwise.
func (m *StatusManager) IsDegraded() bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Controllers can explicitly set us degraded.
	if m.degraded {
		return true
	}

	// Otherwise, we might be degraded due to failing pods.
	if m.progressing == nil || m.failing == nil {
		// We haven't learned our state yet. Return false.
		return false
	}
	return len(m.failing) != 0
}

// syncState syncs our internal state with that of the cluster. It returns true if we've synced
// and returns false if we are still waiting for information.
func (m *StatusManager) syncState() bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	progressing := []string{}
	failing := []string{}
	numDaemonSets := len(m.daemonsets)
	numDeployments := len(m.deployments)
	if len(m.daemonsets) > 0 {
		// For each daemonset, check its rollout status.
		for _, dsnn := range m.daemonsets {
			ds := &appsv1.DaemonSet{}
			err := m.client.Get(context.TODO(), dsnn, ds)
			if err != nil {
				log.WithValues("error", err).Info("Error querying daemonset")
				continue
			}
			if ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled {
				progressing = append(progressing, fmt.Sprintf("DaemonSet %q update is rolling out (%d out of %d updated)", dsnn.String(), ds.Status.UpdatedNumberScheduled, ds.Status.DesiredNumberScheduled))
			} else if ds.Status.NumberUnavailable > 0 {
				progressing = append(progressing, fmt.Sprintf("DaemonSet %q is not available (awaiting %d nodes)", dsnn.String(), ds.Status.NumberUnavailable))
			} else if ds.Status.NumberAvailable == 0 {
				progressing = append(progressing, fmt.Sprintf("DaemonSet %q is not yet scheduled on any nodes", dsnn.String()))
			} else if ds.Generation > ds.Status.ObservedGeneration {
				progressing = append(progressing, fmt.Sprintf("DaemonSet %q update is being processed (generation %d, observed generation %d)", dsnn.String(), ds.Generation, ds.Status.ObservedGeneration))
			}

			// Check if any pods within the daemonset are failing.
			if f := m.podsFailing(ds.Spec.Selector, ds.Namespace); f != "" {
				failing = append(failing, f)
			}
		}
	}
	if len(m.deployments) > 0 {
		for _, depnn := range m.deployments {
			dep := &appsv1.Deployment{}
			err := m.client.Get(context.TODO(), depnn, dep)
			if err != nil {
				log.WithValues("error", err).Info("Error querying deployment")
				continue
			}
			if dep.Status.UnavailableReplicas > 0 {
				progressing = append(progressing, fmt.Sprintf("Deployment %q is not available (awaiting %d replicas)", depnn.String(), dep.Status.UnavailableReplicas))
			} else if dep.Status.AvailableReplicas == 0 {
				progressing = append(progressing, fmt.Sprintf("Deployment %q is not yet scheduled on any nodes", depnn.String()))
			} else if dep.Status.ObservedGeneration < dep.Generation {
				progressing = append(progressing, fmt.Sprintf("Deployment %q update is being processed (generation %d, observed generation %d)", depnn.String(), dep.Generation, dep.Status.ObservedGeneration))
			}

			// Check if any pods within the deployment are failing.
			if f := m.podsFailing(dep.Spec.Selector, dep.Namespace); f != "" {
				failing = append(failing, f)
			}
		}
	}

	if numDeployments+numDaemonSets > 0 {
		// We have been told about the resources we need to watch - set state before unlocking.
		m.progressing = progressing
		m.failing = failing
		return true
	} else {
		// We don't know about any resources. Clear internal state to indicate this.
		m.progressing = nil
		m.failing = nil
	}
	return false
}

// podsFailing takes a selector and returns if any of the pods that match it are failing. Failing pods are defined
// to be in CrashLoopBackOff state.
func (m *StatusManager) podsFailing(selector *metav1.LabelSelector, namespace string) string {
	l := corev1.PodList{}
	s, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		panic(err)
	}
	opts := client.ListOptions{
		LabelSelector: s,
		Namespace:     namespace,
	}
	m.client.List(context.TODO(), &opts, &l)
	for _, p := range l.Items {
		if p.Status.Phase == corev1.PodFailed {
			return fmt.Sprintf("Pod %s/%s has failed", p.Namespace, p.Name)
		}
		for _, c := range p.Status.InitContainerStatuses {
			if msg := m.containerErrorMessage(p, c); msg != "" {
				return msg
			}
		}
		for _, c := range p.Status.ContainerStatuses {
			if msg := m.containerErrorMessage(p, c); msg != "" {
				return msg
			}
		}
	}
	return ""
}

func (m StatusManager) containerErrorMessage(p corev1.Pod, c corev1.ContainerStatus) string {
	if c.State.Waiting != nil {
		// Check well-known error states here and report an appropriate mesage to the end user.
		if c.State.Waiting.Reason == "CrashLoopBackOff" {
			return fmt.Sprintf("Pod %s/%s has crash looping container: %s", p.Namespace, p.Name, c.Name)
		} else if c.State.Waiting.Reason == "ImagePullBackOff" || c.State.Waiting.Reason == "ErrImagePull" {
			return fmt.Sprintf("Pod %s/%s failed to pull container image for: %s", p.Namespace, p.Name, c.Name)
		}
	}
	if c.State.Terminated != nil {
		if c.State.Terminated.Reason == "Error" {
			return fmt.Sprintf("Pod %s/%s has terminated container: %s", p.Namespace, p.Name, c.Name)
		}
	}
	return ""
}

func (m *StatusManager) set(conditions ...operator.TigeraStatusCondition) {
	if !m.enabled {
		// Never set any conditions unless the status manager is enabled.
		return
	}

	ts := &operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: m.component}}
	err := m.client.Get(context.TODO(), types.NamespacedName{Name: m.component}, ts)
	isNotFound := errors.IsNotFound(err)
	if err != nil && !isNotFound {
		log.WithValues("error", err).Info("Failed to get TigeraStatus %q: %v", m.component, err)
		return
	}

	// Make a copy for comparing later.
	old := ts.DeepCopy()

	// Go through each new condition. If we have an existing condition of the same type, then simply
	// update it. Otherwise add a new one.
	for _, condition := range conditions {
		found := false
		for i, c := range ts.Status.Conditions {
			if c.Type == condition.Type {
				// If the status has changed, update the transition time.
				condition.LastTransitionTime = c.LastTransitionTime
				if c.Status != condition.Status {
					condition.LastTransitionTime = metav1.NewTime(time.Now())
				}
				ts.Status.Conditions[i] = condition
				found = true
			}
		}
		if !found {
			condition.LastTransitionTime = metav1.NewTime(time.Now())
			ts.Status.Conditions = append(ts.Status.Conditions, condition)
		}
	}

	// If nothing has changed, we don't need to update in the API.
	if reflect.DeepEqual(ts.Status.Conditions, old.Status.Conditions) {
		return
	}

	// Update the object in the API, creating it if necessary.
	if isNotFound {
		if err = m.client.Create(context.TODO(), ts); err != nil {
			log.WithValues("error", err).Info("Failed to create tigera status")
		}
	}
	if err = m.client.Status().Update(context.TODO(), ts); err != nil {
		log.WithValues("error", err).Info("Failed to update tigera status")
	}
}

func (m *StatusManager) setAvailable(reason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentAvailable, Status: operator.ConditionTrue, Reason: reason, Message: msg},
	}
	m.set(conditions...)
}

func (m *StatusManager) setDegraded(reason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentDegraded, Status: operator.ConditionTrue, Reason: reason, Message: msg},
	}
	m.degraded = true
	m.set(conditions...)
}

func (m *StatusManager) setProgressing(reason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentProgressing, Status: operator.ConditionTrue, Reason: reason, Message: msg},
	}
	m.set(conditions...)
}

func (m *StatusManager) clearDegraded() {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentDegraded, Status: operator.ConditionFalse},
	}
	m.set(conditions...)
}

func (m *StatusManager) clearProgressing() {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentProgressing, Status: operator.ConditionFalse},
	}
	m.set(conditions...)
}

func (m *StatusManager) clearAvailable() {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentAvailable, Status: operator.ConditionFalse},
	}
	m.set(conditions...)
}

func (m *StatusManager) progressingMessage() string {
	m.lock.Lock()
	defer m.lock.Unlock()
	return strings.Join(m.progressing, "\n")
}

func (m *StatusManager) degradedMessage() string {
	m.lock.Lock()
	defer m.lock.Unlock()
	msgs := []string{}
	if m.explicitDegradedMsg != "" {
		msgs = append(msgs, m.explicitDegradedMsg)
	}
	msgs = append(msgs, m.failing...)
	return strings.Join(msgs, "\n")
}

func (m *StatusManager) degradedReason() string {
	m.lock.Lock()
	defer m.lock.Unlock()
	reasons := []string{}
	if m.explicitDegradedReason != "" {
		reasons = append(reasons, m.explicitDegradedReason)
	}
	if len(m.failing) != 0 {
		reasons = append(reasons, "Some pods are failing")
	}
	return strings.Join(reasons, "; ")
}
