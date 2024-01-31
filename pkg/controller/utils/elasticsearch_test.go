// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	elastic "github.com/olivere/elastic/v7"

	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	baseURI   = "http://127.0.0.1:9200"
	indexName = "tigera_secure_ee_test_index"
)

var newPolicies bool
var _ = Describe("Elasticsearch tests", func() {
	Context("ILM", func() {
		var (
			eClient     *esClient
			ctx         context.Context
			rolloverMax = resource.MustParse(fmt.Sprintf("%dGi", DefaultMaxIndexSizeGi))
		)
		BeforeEach(func() {
			client := &http.Client{
				Transport: http.RoundTripper(&testRoundTripper{}),
			}
			eClient = mockElasticClient(client, baseURI)
			ctx = context.Background()
		})

		It("max rollover size should be set if ES disk is large", func() {
			Expect(nil).Should(BeNil())
			defaultStorage := resource.MustParse(fmt.Sprintf("%dGi", 800))
			expectedRolloverSize := rolloverMax.Value()

			totalEsStorage := defaultStorage.Value()
			// using flow logs disk allocation value
			diskPercentage := 0.7
			diskForLogType := 0.9

			rolloverSize := calculateRolloverSize(totalEsStorage, diskPercentage, diskForLogType)
			Expect(rolloverSize).To(Equal(fmt.Sprintf("%db", expectedRolloverSize)))
		})
		It("rollover age", func() {
			By("for retention period lesser than retention factor")
			Expect("1d").To(Equal(calculateRolloverAge(2)))

			By("for retention period 0")
			Expect("1h").To(Equal(calculateRolloverAge(0)))
		})
		It("apply new lifecycle policy", func() {
			newPolicies = true
			totalDiskSize := resource.MustParse("100Gi")
			pd := buildILMPolicy(totalDiskSize.Value(), 0.7, .9, 10)

			err := eClient.createOrUpdatePolicies(ctx, map[string]policyDetail{
				indexName: pd,
			})
			Expect(err).To(BeNil())
		})
		It("update existing lifecycle policy", func() {
			newPolicies = false
			totalDiskSize := resource.MustParse("100Gi")
			pd := buildILMPolicy(totalDiskSize.Value(), 0.7, .9, 5)
			err := eClient.createOrUpdatePolicies(ctx, map[string]policyDetail{
				indexName: pd,
			})
			Expect(err).To(BeNil())
		})
	})
})

type testRoundTripper struct {
	e error
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.e != nil {
		return nil, t.e
	}
	switch req.Method {
	case "HEAD":
		switch req.URL.String() {
		case baseURI:
			return &http.Response{
				StatusCode: 200,
				Request:    req,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
	case "GET":
		switch req.URL.String() {
		case baseURI + "/_ilm/policy/" + indexName + "_policy":
			if newPolicies {
				return &http.Response{
					StatusCode: 404,
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: 200,
				Request:    req,
				Body:       mustOpen("test_files/02_get_policy.json"),
			}, nil
		}
	case "POST":
	case "PUT":
		switch req.URL.String() {
		case baseURI + "/_ilm/policy/" + indexName + "_policy":
			if newPolicies {
				actualBody, err := io.ReadAll(req.Body)
				Expect(err).To(BeNil())

				jsonFile, err := os.Open("test_files/01_put_policy.json")
				Expect(err).To(BeNil())
				defer jsonFile.Close()
				expectedBody, _ := io.ReadAll(jsonFile)
				Expect(actualBody).To(MatchJSON(expectedBody))

				return &http.Response{
					StatusCode: 200,
					Request:    req,
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
				}, nil
			}
			actualBody, err := io.ReadAll(req.Body)
			Expect(err).To(BeNil())

			jsonFile, err := os.Open("test_files/02_put_policy.json")
			Expect(err).To(BeNil())
			defer jsonFile.Close()
			expectedBody, _ := io.ReadAll(jsonFile)
			Expect(actualBody).To(MatchJSON(expectedBody))

			return &http.Response{
				StatusCode: 200,
				Request:    req,
				Body:       io.NopCloser(bytes.NewBufferString("{}")),
			}, nil
		}
	}

	if os.Getenv("ELASTIC_TEST_DEBUG") == "yes" {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", req.Method, req.URL)
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()
			body := string(b)
			req.Body = io.NopCloser(bytes.NewReader(b))
			_, _ = fmt.Fprintln(os.Stderr, body)
		}
	}

	return &http.Response{
		Request:    req,
		StatusCode: 500,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func mustOpen(name string) io.ReadCloser {
	f, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	return f
}

func mockElasticClient(h *http.Client, url string) *esClient {
	options := []elastic.ClientOptionFunc{
		elastic.SetHttpClient(h),
		elastic.SetURL(url),
		elastic.SetSniff(false),
	}
	client, err := elastic.NewClient(options...)
	Expect(err).To(BeNil())

	ecl := esClient{}
	ecl.client = client
	return &ecl
}
