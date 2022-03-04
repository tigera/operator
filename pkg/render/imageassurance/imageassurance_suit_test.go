// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
)

func TestRender(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../../report/imageassurance_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/imageassurance/imageassurance Suite", []Reporter{junitReporter})
}
