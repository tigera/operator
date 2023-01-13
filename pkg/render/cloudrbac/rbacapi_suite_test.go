// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package cloudrbac

import (
	"testing"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"
)

func TestRender(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/render_rbacapi_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/render/cloudrbac Suite", []Reporter{junitReporter})
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
}, 60)
