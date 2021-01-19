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

package authentication

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/controller/status"

	"github.com/onsi/ginkgo/reporters"
	oprv1 "github.com/tigera/operator/api/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestStatus(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/authentication_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/controller/authentication Suite", []Reporter{junitReporter})
}

// Expose the construction of the reconciler through this test file.
func NewReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	provider oprv1.Provider,
	status status.StatusManager) *ReconcileAuthentication {
	return &ReconcileAuthentication{
		client:   client,
		scheme:   scheme,
		provider: provider,
		status:   status,
	}
}
