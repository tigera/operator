package statik

import (
	"fmt"
	"io/ioutil"

	"github.com/rakyll/statik/fs"
	_ "github.com/tigera/operator/statik"
)

// getStatikFile gets the static file embeded into the binary using statik library (https://github.com/rakyll/statik).
// All static files are located in statik/files. statik/statik.go is the source file that is generated
// from the static files. It can be recreated using the following command.
// "statik -src=/home/suresh/go/src/github.com/tigera/operator/statik/files"
func GetStatikFile(path string) (string, error) {

	// initialize statik file system
	sfs, err := fs.New()

	if err != nil {
		return "", fmt.Errorf("unable to initiate statik file system %s", err)
	}

	// Access individual files by their paths.
	r, err := sfs.Open(path)
	if err != nil {
		return "", fmt.Errorf("unable to open file with path %s, %s", path, err)
	}
	defer r.Close()

	contents, err := ioutil.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("unable to open file with path %s, %s", path, err)
	}

	return string(contents), nil
}
