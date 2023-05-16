// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package testsupport

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"regexp"

	. "github.com/onsi/gomega"
	yaml2 "gopkg.in/yaml.v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

var (
	update = flag.Bool("update", false, "update the golden files of this test")
)

func init() {
	yaml2.FutureLineWrap() // disable line wrapping for golden yaml tests
}

// ExpectMatchesGoldenYaml compares value with its golden file
//
// NOTE: you can regenerate golden files from the actual test files by running ginkgo with the `-update` flag, e.g. `ginkgo -v "--focus=Some Test" -- -update`
func ExpectMatchesGoldenYaml(filename string, actual any) {
	var err error
	goldenPath := fmt.Sprintf("testdata/%s-golden.yaml", filename)
	actualPath := fmt.Sprintf("testdata/%s-actual.yaml", filename)

	var actualBytes []byte

	switch a := actual.(type) {
	case []byte:
		actualBytes = a
	case []client.Object:
		// by default a slice will be written as an array, so instead doing one element at a time and adding the --- separator
		var buf bytes.Buffer
		for i := range a {
			if i > 0 {
				buf.WriteString("\n---\n")
			}
			marshalled, err := yaml.Marshal(a[i])
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			buf.Write(marshalled)
		}
		actualBytes = buf.Bytes()
	default:
		actualBytes, err = yaml.Marshal(actual)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
	}

	// Remove any values that vary from run to run:
	//
	// pod template hashes
	actualBytes = regexp.MustCompile(`(hash.operator.tigera.io.*: )[a-z0-9]+`).ReplaceAll(actualBytes, []byte("$1 redacted-hash-value"))
	//
	// certs, note: `base64("-----BEGIN CERTIFICATE-----")=="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"`
	actualBytes = regexp.MustCompile(`LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t.*`).ReplaceAll(actualBytes, []byte("redacted-certificate-data"))

	if *update {
		ExpectWithOffset(1, os.WriteFile(goldenPath, actualBytes, 0755)).ToNot(HaveOccurred())
	}

	expectedBytes, err := os.ReadFile(goldenPath)
	ExpectWithOffset(1, err).ToNot(HaveOccurred())

	actualString := string(actualBytes)
	expectedString := string(expectedBytes)

	// write the actual file only if it is different to the expected, otherwise remove it
	if actualString != expectedString {
		ExpectWithOffset(1, os.WriteFile(actualPath, actualBytes, 0755)).ToNot(HaveOccurred())
	} else {
		_ = os.Remove(actualPath)
	}

	ExpectWithOffset(1, actualString).To(Equal(expectedString),
		fmt.Sprintf("goldenFile: %s, actualFile: %s", goldenPath, actualPath),
	)
}
