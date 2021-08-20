// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package externalelasticsearch

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"
)

func TestRender(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../../report/externalelasticsearch_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/render/logstorage/externalelasticsearch Suite", []Reporter{junitReporter})
}
