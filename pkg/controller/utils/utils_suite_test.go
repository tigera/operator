package utils_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
)

func TestUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/utils_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/controller/utils Suite", []Reporter{junitReporter})
}
