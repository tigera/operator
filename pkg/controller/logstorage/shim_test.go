// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

// This file is here so that we can export a constructor to be used by the tests in the logstorage_test package, but since
// this is an _test file it will only be available for when running tests.
package logstorage

import (
	"context"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewReconcilerWithShims(
	cli client.Client,
	schema *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	esCliCreator utils.ElasticsearchClientCreator,
	clusterDomain string,
	tierWatchReady *utils.ReadyFlag) (*ReconcileLogStorage, error) {

	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
	}

	return newReconciler(cli, schema, status, opts, esCliCreator, tierWatchReady)
}
