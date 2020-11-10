// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

// This file is here so that we can set a dummy elastic client to be used by the tests, since
// this is an _test file it will only be available for when running tests.
package utils

import (
	"net/http"

	"github.com/olivere/elastic/v7"
	. "github.com/onsi/gomega"
)

func NewElasticClientShims(h *http.Client, url string) esClient {
	options := []elastic.ClientOptionFunc{
		elastic.SetHttpClient(h),
		elastic.SetURL(url),
		elastic.SetSniff(false),
	}
	client, err := elastic.NewClient(options...)
	Expect(err).To(BeNil())

	ecl := esClient{}
	ecl.client = client
	return ecl
}
