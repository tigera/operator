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
