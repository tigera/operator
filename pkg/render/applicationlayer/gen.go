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
