// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package runtimesecurity

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
)

func TestRender(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../../report/runtimesecurity_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/imageassurance/runtimesecurity Suite", []Reporter{junitReporter})
}
