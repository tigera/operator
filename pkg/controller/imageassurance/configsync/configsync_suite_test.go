// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package configsync_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"
	uzap "go.uber.org/zap"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestStatus(t *testing.T) {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true), zap.Level(uzap.NewAtomicLevelAt(uzap.DebugLevel))))
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../../report/configsync_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/controller/configsync Config Sync Suite", []Reporter{junitReporter})
}
