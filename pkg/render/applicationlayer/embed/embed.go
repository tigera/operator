package embed

import (
	"embed"
	"fmt"
	"io/fs"
)

var (
	FS fs.FS
	//go:embed coreruleset
	crsFS embed.FS
)

func init() {
	var err error
	FS, err = fs.Sub(crsFS, "coreruleset")
	if err != nil {
		panic(err)
	}
}

func AsMap() (map[string]string, error) {
	res := make(map[string]string)
	var walkFn fs.WalkDirFunc = func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return err
		}

		if b, err := fs.ReadFile(FS, path); err != nil {
			return err
		} else {
			res[d.Name()] = string(b)
		}
		return nil
	}

	if err := fs.WalkDir(FS, ".", walkFn); err != nil {
		return nil, fmt.Errorf("failed to walk core ruleset files (%w)", err)
	}

	return res, nil
}
