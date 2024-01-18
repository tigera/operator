// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// DeleteAllowTigeraTierAndExpectWait deletes the tier resource and expects the Reconciler issues a degraded status, waiting for
// the tier to become available before progressing its status further. Assumes that mockStatus has any required initial status
// progression expectations set, and that the Reconciler utilizes the mockStatus object. Assumes the tier resource has been created.
func DeleteAllowTigeraTierAndExpectWait(ctx context.Context, c client.Client, r reconcile.Reconciler, mockStatus *status.MockStatus) {
	err := c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})
	Expect(err).ShouldNot(HaveOccurred())
	mockStatus.On("SetDegraded", operator.ResourceNotReady, "Waiting for allow-tigera tier to be created, see the 'tiers' TigeraStatus for more information", "tiers.projectcalico.org \"allow-tigera\" not found", mock.Anything).Return()

	_, err = r.Reconcile(ctx, reconcile.Request{})
	Expect(err).ShouldNot(HaveOccurred())
	mockStatus.AssertExpectations(GinkgoT())
}

// ExpectWaitForTierWatch expects the Reconciler issues a degraded status, waiting for a Tier watch to be established.
// Assumes that mockStatus has any required initial status progression expectations set, and that the Reconciler utilizes
// the mockStatus object.
func ExpectWaitForTierWatch(ctx context.Context, r reconcile.Reconciler, mockStatus *status.MockStatus) {
	ExpectWaitForWatch(ctx, r, mockStatus, "Waiting for Tier watch to be established")
}

// ExpectWaitForWatch expects the Reconciler issues a degraded status, waiting for a watch to be established.
// Assumes that mockStatus has any required initial status progression expectations set, and that the Reconciler utilizes
// the mockStatus object.
func ExpectWaitForWatch(ctx context.Context, r reconcile.Reconciler, mockStatus *status.MockStatus, message string) {
	mockStatus.On("SetDegraded", operator.ResourceNotReady, message, mock.Anything, mock.Anything).Return()
	_, err := r.Reconcile(ctx, reconcile.Request{})
	Expect(err).ShouldNot(HaveOccurred())
	mockStatus.AssertExpectations(GinkgoT())
}
