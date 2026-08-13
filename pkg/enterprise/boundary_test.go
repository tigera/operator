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
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const modulePath = "github.com/tigera/operator/"

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
}

// knownExceptions are the core files that still name an Enterprise resource. The
// list must only ever shrink.
var knownExceptions = []string{
	"cmd/main.go",
	"pkg/controller/secrets/tenant_controller.go",
	"pkg/controller/tiers/tiers_controller.go",
}

var _ = Describe("Enterprise render package boundary", func() {
	It("is not crossed by core code", func() {
		var offenders []string

		root := filepath.Join("..", "..")
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)

			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == "vendor" || isEnterprise(rel) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
				return nil
			}
			if isEnterprise(rel) || contains(knownExceptions, rel) {
				return nil
			}

			f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}
			for _, imp := range f.Imports {
				p, quoteErr := strconv.Unquote(imp.Path.Value)
				if quoteErr != nil {
					return quoteErr
				}
				if isEnterpriseImport(p) {
					offenders = append(offenders, rel+" imports "+p)
				}
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(offenders).To(BeEmpty(), "core code must reach Enterprise renderers through pkg/extensions")
	})
})

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
	for _, prefix := range enterpriseRender {
		if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
