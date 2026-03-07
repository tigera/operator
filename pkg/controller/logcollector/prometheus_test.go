// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logcollector

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/tigera/operator/pkg/controller/status"
)

// mockPrometheusClient implements PrometheusClient for testing.
type mockPrometheusClient struct {
	mock.Mock
}

func (m *mockPrometheusClient) QueryDataFlowing(ctx context.Context, query string) (bool, error) {
	args := m.Called(ctx, query)
	return args.Bool(0), args.Error(1)
}

var _ = Describe("checkESDataFlow", func() {
	var (
		ctx        context.Context
		mockStatus *status.MockStatus
		mockProm   *mockPrometheusClient
		r          *ReconcileLogCollector
	)

	BeforeEach(func() {
		ctx = context.Background()
		mockStatus = &status.MockStatus{}
		mockProm = &mockPrometheusClient{}
		r = &ReconcileLogCollector{
			status:     mockStatus,
			promClient: mockProm,
		}
	})

	AfterEach(func() {
		mockProm.AssertExpectations(GinkgoT())
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should set info when data was sent in the last 5 minutes", func() {
		mockProm.On("QueryDataFlowing", ctx, esDataFlowInfoQuery).Return(true, nil)

		mockStatus.On("ClearWarning", esDataFlowWarningKey).Return()
		mockStatus.On("SetInfo", esDataFlowWarningKey, "Data was successfully sent to Elasticsearch in the last 5 minutes").Return()

		r.checkESDataFlow(ctx, nil)
	})

	It("should set warning when no data was sent in the last 30 minutes", func() {
		mockProm.On("QueryDataFlowing", ctx, esDataFlowInfoQuery).Return(false, nil)
		mockProm.On("QueryDataFlowing", ctx, esDataFlowWarningQuery).Return(false, nil)

		mockStatus.On("ClearInfo", esDataFlowWarningKey).Return()
		mockStatus.On("SetWarning", esDataFlowWarningKey, "Warning: No data has been sent to Elasticsearch in the last 30 minutes").Return()

		r.checkESDataFlow(ctx, nil)
	})

	It("should clear both info and warning when data was sent in the last 30 minutes but not the last 5", func() {
		mockProm.On("QueryDataFlowing", ctx, esDataFlowInfoQuery).Return(false, nil)
		mockProm.On("QueryDataFlowing", ctx, esDataFlowWarningQuery).Return(true, nil)

		mockStatus.On("ClearInfo", esDataFlowWarningKey).Return()
		mockStatus.On("ClearWarning", esDataFlowWarningKey).Return()

		r.checkESDataFlow(ctx, nil)
	})

	It("should not update status when the 5m query fails", func() {
		mockProm.On("QueryDataFlowing", ctx, esDataFlowInfoQuery).Return(false, fmt.Errorf("connection refused"))

		r.checkESDataFlow(ctx, nil)

		// Prometheus client should be reset for next attempt.
		Expect(r.promClient).To(BeNil())
	})

	It("should not update status when the 30m query fails", func() {
		mockProm.On("QueryDataFlowing", ctx, esDataFlowInfoQuery).Return(false, nil)
		mockProm.On("QueryDataFlowing", ctx, esDataFlowWarningQuery).Return(false, fmt.Errorf("timeout"))

		r.checkESDataFlow(ctx, nil)

		Expect(r.promClient).To(BeNil())
	})
})
