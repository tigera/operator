// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package embed

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmbed(t *testing.T) {
	for _, fileName := range []string{
		// bare FS embed as sub. coreruleset prefix stripped
		"modsecdefault.conf",
		"crs-setup.conf",
		"tigera.conf",
		"unicode.mapping",
		// subdirectory 'rules' intact
		"rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example",
		"rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	} {
		_, err := FS.Open(fileName)
		require.NoError(t, err)
	}
}

func TestEmbedAsMap(t *testing.T) {
	fileMap, err := AsMap()
	require.NoError(t, err)
	for _, fileName := range []string{
		"modsecdefault.conf",
		"crs-setup.conf",
		"unicode.mapping",
		// rules directory is stripped because of fs.Walk uses file entry name
		"REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example",
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	} {
		_, ok := fileMap[fileName]
		require.True(t, ok)
	}
}
