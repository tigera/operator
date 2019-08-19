package status

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	v1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var log = logf.Log.WithName("status_manager")

type StatusManager struct {
	client      client.Client
	component   string
	daemonsets  []types.NamespacedName
	deployments []types.NamespacedName
	lock        sync.Mutex
	available   bool
	degraded    bool
	enabled     bool
}

func New(client client.Client, component string) *StatusManager {
	return &StatusManager{
		client:      client,
		component:   component,
		daemonsets:  []types.NamespacedName{},
		deployments: []types.NamespacedName{},
	}
}

func (m *StatusManager) Run() {
	go func() {
		// Loop forever, periodically checking dependent objects for their state.
		for {
			m.lock.Lock()
			progressing := []string{}
			numDaemonSets := len(m.daemonsets)
			numDeployments := len(m.deployments)
			if len(m.daemonsets) > 0 {
				// For each daemonset, check its rollout status.
				for _, dsnn := range m.daemonsets {
					ds := &v1.DaemonSet{}
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
				}
			}
			if len(m.deployments) > 0 {
				for _, depnn := range m.deployments {
					dep := &v1.Deployment{}
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
				}
			}

			// Get current state within the lock.
			degraded := m.degraded
			m.lock.Unlock()

			// If there are any progressing, then set it so.
			if len(progressing) != 0 && !degraded {
				// If we're progressing then set a shorter timeout.
				m.SetProgressing("Not all pods are ready", strings.Join(progressing, "\n"))
				time.Sleep(5 * time.Second)
				continue
			} else if degraded {
				// If we're degraded, then also set a shorter timeout.
				time.Sleep(5 * time.Second)
				continue
			} else if numDaemonSets > 0 || numDeployments > 0 {
				m.SetAvailable("All objects available", "")
			}
			time.Sleep(30 * time.Second)
		}
	}()
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

func (m *StatusManager) SetAvailable(reason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentAvailable, Status: operator.ConditionTrue, Reason: reason, Message: msg},
		{Type: operator.ComponentProgressing, Status: operator.ConditionFalse},
	}
	m.available = true
	m.degraded = false
	m.set(conditions...)
}

func (m *StatusManager) SetDegraded(reason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentDegraded, Status: operator.ConditionTrue, Reason: reason, Message: msg},
		{Type: operator.ComponentProgressing, Status: operator.ConditionFalse},
	}
	m.available = false
	m.degraded = true
	m.set(conditions...)
}

func (m *StatusManager) SetProgressing(reason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentProgressing, Status: operator.ConditionTrue, Reason: reason, Message: msg},
	}
	m.set(conditions...)
}

func (m *StatusManager) ClearDegraded() {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentDegraded, Status: operator.ConditionFalse},
	}
	m.degraded = false
	m.set(conditions...)
}

func (m *StatusManager) ClearAvailable() {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentAvailable, Status: operator.ConditionFalse},
	}
	m.available = false
	m.set(conditions...)
}

func (m *StatusManager) Enable() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.enabled = true
}

func (m *StatusManager) SetDaemonsets(ds []types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.daemonsets = ds
}

func (m *StatusManager) SetDeployments(deps []types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.deployments = deps
}

func (m *StatusManager) IsAvailable() bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.available
}
