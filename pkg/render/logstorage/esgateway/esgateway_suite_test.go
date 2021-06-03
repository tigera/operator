package esgateway

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"
)

func TestRender(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../../report/esgateway_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/logstorage/esgateway Suite", []Reporter{junitReporter})
}
