// Copyright (c) 2023-2023 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var elog = logf.Log.WithName("eventhandler").WithName("EnqueueAllTenants")

func EnqueueAllTenants(c client.Client) handler.EventHandler {
	return &enqueueAllTenants{client: c}
}

// enqueueAllTenants queues updates for all tenants in the cluster.
type enqueueAllTenants struct {
	client client.Client
}

// Create is called in response to an create event - e.g. Pod Creation.
func (h *enqueueAllTenants) Create(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	elog.V(2).Info("Create event triggered reconciliation for all tenants", "event", e)
	h.enqueue(q)
}

// Update is called in response to an update event -  e.g. Pod Updated.
func (h *enqueueAllTenants) Update(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	elog.V(2).Info("Update event triggered reconciliation for all tenants", "event", e)
	h.enqueue(q)
}

// Delete is called in response to a delete event - e.g. Pod Deleted.
func (h *enqueueAllTenants) Delete(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	elog.V(2).Info("Delete event triggered reconciliation for all tenants", "event", e)
	h.enqueue(q)
}

// Generic is called in response to an event of an unknown type or a synthetic event triggered as a cron or
// external trigger request - e.g. reconcile Autoscaling, or a Webhook.
func (h *enqueueAllTenants) Generic(e event.GenericEvent, q workqueue.RateLimitingInterface) {
	elog.V(2).Info("Generic event triggered reconciliation for all tenants", "event", e)
	h.enqueue(q)
}

func (h *enqueueAllTenants) enqueue(q workqueue.RateLimitingInterface) {
	tenants := h.getAllTenants()
	for _, t := range tenants {
		q.Add(reconcile.Request{NamespacedName: t})
	}
}

func (h *enqueueAllTenants) getAllTenants() []types.NamespacedName {
	allTenants := operatorv1.TenantList{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := h.client.List(ctx, &allTenants)
	if err != nil {
		elog.Error(err, "Error querying tenants, cannot trigger Reconcile")
		return nil
	}

	names := []types.NamespacedName{}
	for _, tenant := range allTenants.Items {
		names = append(names, types.NamespacedName{Name: tenant.Name, Namespace: tenant.Namespace})
	}
	return names
}
