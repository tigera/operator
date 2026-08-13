// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package enterprise_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	modulePath = "github.com/tigera/operator/"
	apiPath    = "github.com/tigera/operator/api/v1"
)

// enterpriseRender are the render packages that only Calico Enterprise installs. Core
// code must not reach into them.
var enterpriseRender = []string{
	"pkg/render/applicationlayer",
	"pkg/render/egressgateway",
	"pkg/render/intrusiondetection",
	"pkg/render/logcollector",
	"pkg/render/logstorage",
	"pkg/render/manager",
	"pkg/render/monitor",
	"pkg/render/nonclusterhost",
}

// enterpriseControllers are the packages an Enterprise-only controller lives in, so
// they may import the packages above.
var enterpriseControllers = []string{
	"pkg/controller/applicationlayer",
	"pkg/controller/authentication",
	"pkg/controller/egressgateway",
	"pkg/controller/intrusiondetection",
	"pkg/controller/istio/waypoint",
	"pkg/controller/logcollector",
	"pkg/controller/logstorage",
	"pkg/controller/manager",
	"pkg/controller/monitor",
	"pkg/controller/nonclusterhost",
	"pkg/controller/packetcapture",
	"pkg/controller/policyrecommendation",
	"pkg/enterprise",
}

// enterpriseRenderFiles are the Enterprise-only files that still sit in the shared
// pkg/render package rather than a package of their own.
var enterpriseRenderFiles = []string{
	"pkg/render/dex",
	"pkg/render/guardian",
	"pkg/render/intrusion_detection",
	"pkg/render/logcollector",
	"pkg/render/logstorage",
	"pkg/render/manager",
	"pkg/render/packet_capture_api",
	"pkg/render/policyrecommendation",
	"pkg/render/tenant",
}

// knownExceptions are the core files that still import Enterprise-only code. The
// list must only ever shrink.
var knownExceptions = []string{
	"cmd/main.go",
	"pkg/controller/secrets/tenant_controller.go",
	"pkg/controller/tiers/tiers_controller.go",
}

// enterpriseKinds are the operator API kinds that only Calico Enterprise installs.
// The OSS operator does not ship their CRDs.
var enterpriseKinds = []string{
	"ApplicationLayer",
	"Authentication",
	"EgressGateway",
	"IntrusionDetection",
	"LogCollector",
	"LogStorage",
	"ManagementCluster",
	"Manager",
	"Monitor",
	"NonClusterHost",
	"PacketCaptureAPI",
	"PolicyRecommendation",
	"TLSPassThroughRoute",
	"TLSTerminatedRoute",
	"Tenant",
}

// knownKindExceptions are the core files that still name an Enterprise-only kind. The
// list must only ever shrink.
var knownKindExceptions = []string{
	"pkg/controller/apiserver/apiserver_controller.go",
	"pkg/controller/secrets/tenant_controller.go",
	"pkg/controller/tiers/tiers_controller.go",
	"pkg/render/common/cloudconfig/cloudconfig.go",
	"pkg/render/kubecontrollers/kube-controllers.go",
}

var _ = Describe("Enterprise boundary", func() {
	var renderImports, kindRefs []string

	BeforeEach(func() {
		var err error
		renderImports, kindRefs, err = scanCore()
		Expect(err).NotTo(HaveOccurred())
	})

	It("is not crossed by an Enterprise render import", func() {
		Expect(renderImports).To(BeEmpty(), "core code must reach Enterprise renderers through pkg/extensions")
	})

	It("is not crossed by an Enterprise API kind reference", func() {
		Expect(kindRefs).To(BeEmpty(), "core code must not name an Enterprise-only operator API kind")
	})
})

// scanCore walks every non-Enterprise Go file and reports the two ways core code can
// reach Enterprise-only code.
func scanCore() (renderImports, kindRefs []string, err error) {
	root := filepath.Join("..", "..")
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" || rel == "api" || isEnterprise(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || isEnterprise(rel) {
			return nil
		}

		f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}

		if !contains(knownExceptions, rel) {
			for _, imp := range f.Imports {
				p, quoteErr := strconv.Unquote(imp.Path.Value)
				if quoteErr != nil {
					return quoteErr
				}
				if isEnterpriseImport(p) {
					renderImports = append(renderImports, rel+" imports "+p)
				}
			}
		}
		if !contains(knownKindExceptions, rel) {
			for _, kind := range enterpriseKindsIn(f) {
				kindRefs = append(kindRefs, rel+" names "+kind)
			}
		}
		return nil
	})
	return renderImports, kindRefs, err
}

// isEnterprise reports whether a repo-relative path is Enterprise-only code.
func isEnterprise(rel string) bool {
	for _, prefix := range append(append([]string{}, enterpriseRender...), enterpriseControllers...) {
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			return true
		}
	}
	for _, prefix := range enterpriseRenderFiles {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

func isEnterpriseImport(path string) bool {
	if !strings.HasPrefix(path, modulePath) {
		return false
	}
	pkg := strings.TrimPrefix(path, modulePath)
	if pkg == "pkg/enterprise" || strings.HasPrefix(pkg, "pkg/enterprise/") {
		return true
	}
	for _, prefix := range enterpriseRender {
		if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") {
			return true
		}
	}
	return false
}

// enterpriseKindsIn reports the Enterprise-only API kinds a file selects off its
// operator API import, whatever alias it gave that import.
func enterpriseKindsIn(f *ast.File) []string {
	aliases := map[string]bool{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != apiPath {
			continue
		}
		if imp.Name != nil {
			aliases[imp.Name.Name] = true
		} else {
			aliases["v1"] = true
		}
	}
	if len(aliases) == 0 {
		return nil
	}

	var found []string
	seen := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !aliases[pkg.Name] {
			return true
		}
		kind := enterpriseKindOf(sel.Sel.Name)
		if kind != "" && !seen[kind] {
			seen[kind] = true
			found = append(found, kind)
		}
		return true
	})
	return found
}

// enterpriseKindOf matches a kind and the types generated alongside it.
func enterpriseKindOf(name string) string {
	for _, kind := range enterpriseKinds {
		for _, suffix := range []string{"", "List", "Spec", "Status"} {
			if name == kind+suffix {
				return kind
			}
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
