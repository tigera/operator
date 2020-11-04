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

package utils

import (
	"bytes"
	"context"
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/api/resource"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	baseURI   = "http://127.0.0.1:9200"
	indexName = "tigera_secure_ee_test_index"
)

var newPolicies bool
var _ = Describe("Elasticsearch tests", func() {
	Context("ILM", func() {
		var (
			esClient    EsClient
			ctx         context.Context
			rolloverMax = resource.MustParse(fmt.Sprintf("%dGi", DefaultMaxIndexSizeGi))
		)
		BeforeEach(func() {
			client := &http.Client{
				Transport: http.RoundTripper(&testRoundTripper{}),
			}
			e, err := NewElastic("", "", baseURI, client)
			Expect(err).To(BeNil())
			esClient = EsClient{client: e}
			ctx = context.Background()
		})

		It("max rollover size should be set if ES disk is large", func() {
			fmt.Printf("%#v", esClient)
			Expect(nil).Should(BeNil())
			defaultStorage := resource.MustParse(fmt.Sprintf("%dGi", 800))
			expectedRolloverSize := rolloverMax.Value()

			totalEsStorage := defaultStorage.Value()
			indexDiskAllocation := IndexDiskMapping[0]
			diskPercentage := indexDiskAllocation.TotalDiskPercentage
			diskForLogType := indexDiskAllocation.IndexNameSize["tigera_secure_ee_flows"]

			rolloverSize := CalculateRolloverSize(totalEsStorage, diskPercentage, diskForLogType)
			Expect(rolloverSize).To(Equal(fmt.Sprintf("%db", expectedRolloverSize)))
		})
		It("rollover age", func() {
			By("for retention period lesser than retention factor")
			Expect("1d").To(Equal(CalculateRolloverAge(2)))

			By("for retention period 0")
			Expect("1h").To(Equal(CalculateRolloverAge(0)))
		})
		It("apply new lifecycle policy", func() {
			newPolicies = true
			retention := 10
			rolloverSize := fmt.Sprintf("%db", rolloverMax.Value())
			rolloverAge := "1d"
			err := BuildAndApplyIlmPolicy(ctx, esClient.client, retention, rolloverSize, rolloverAge, indexName)
			Expect(err).To(BeNil())
		})
		It("update existing lifecycle policy", func() {
			newPolicies = false
			retention := 5
			rolloverSize := fmt.Sprintf("%db", rolloverMax.Value())
			rolloverAge := CalculateRolloverAge(retention)
			err := BuildAndApplyIlmPolicy(ctx, esClient.client, retention, rolloverSize, rolloverAge, indexName)
			Expect(err).To(BeNil())
		})
	})
})

type testRoundTripper struct {
	u *url.URL
	e error
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Printf("\n===ROUNDTRIPPER: %#v %#v", req.Method, req.URL.String())
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
				Body:       ioutil.NopCloser(strings.NewReader("")),
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
				actualBody, err := ioutil.ReadAll(req.Body)
				Expect(err).To(BeNil())

				jsonFile, err := os.Open("test_files/01_put_policy.json")
				Expect(err).To(BeNil())
				defer jsonFile.Close()
				expectedBody, _ := ioutil.ReadAll(jsonFile)
				Expect(actualBody).To(MatchJSON(expectedBody))

				return &http.Response{
					StatusCode: 200,
					Request:    req,
					Body:       ioutil.NopCloser(bytes.NewBufferString("{}")),
				}, nil
			}
			actualBody, err := ioutil.ReadAll(req.Body)
			Expect(err).To(BeNil())

			jsonFile, err := os.Open("test_files/02_put_policy.json")
			Expect(err).To(BeNil())
			defer jsonFile.Close()
			expectedBody, _ := ioutil.ReadAll(jsonFile)
			Expect(actualBody).To(MatchJSON(expectedBody))

			return &http.Response{
				StatusCode: 200,
				Request:    req,
				Body:       ioutil.NopCloser(bytes.NewBufferString("{}")),
			}, nil
		}
	}

	if os.Getenv("ELASTIC_TEST_DEBUG") == "yes" {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", req.Method, req.URL)
		if req.Body != nil {
			b, _ := ioutil.ReadAll(req.Body)
			_ = req.Body.Close()
			body := string(b)
			req.Body = ioutil.NopCloser(bytes.NewReader(b))
			_, _ = fmt.Fprintln(os.Stderr, body)
		}
	}

	return &http.Response{
		Request:    req,
		StatusCode: 500,
		Body:       ioutil.NopCloser(strings.NewReader("")),
	}, nil
}

func mustOpen(name string) io.ReadCloser {
	f, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	return f
}
