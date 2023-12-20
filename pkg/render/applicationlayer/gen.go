// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

//go:build ignore

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

var tpl = template.Must(template.New("").Parse(`// THIS IS A GENERATED FILE, PLEASE DO NOT EDIT.
package applicationlayer

var ModsecurityCoreRuleSet = map[string]string{
{{- range $name, $data := . }}
	"{{ $name }}": "{{ $data }}",
{{- end }}
}

`))

func main() {

	fout, err := os.Create("./modsecurityrules.go")
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	} else {
		defer fout.Close()
	}

	directory, err := os.ReadDir("./modsec-core-ruleset")
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	ruleset := make(map[string]string)
	for _, f := range directory {
		if f.IsDir() {
			continue
		}
		if d, err := os.ReadFile(filepath.Join("./modsec-core-ruleset", f.Name())); err == nil {
			ruleset[f.Name()] = base64.StdEncoding.EncodeToString(d)
		} else {
			fmt.Print(err)
			os.Exit(1)
		}
	}

	tpl.Execute(fout, ruleset)
}
