package applicationlayer

import (
	"fmt"
	"io/fs"
	"testing"
)

func TestEmbedContents(t *testing.T) {
	var walkFn fs.WalkDirFunc = func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		if _, err := fs.ReadFile(coreRuleSetFiles, path); err != nil {
			return fmt.Errorf("unreadable file: %w", err)
		}
		return nil
	}
	if err := fs.WalkDir(coreRuleSetFiles, ".", walkFn); err != nil {
		t.Fatal("embed failed: ", err)
	}
}

func TestCoreRulesetMap(t *testing.T) {
	v, err := CoreRuleSetFilesMap()
	if err != nil {
		t.Fatal("fetching embed to map failed: ", err)
	}
	if len(v) == 0 {
		t.Fatal("map is empty")
	}
}
