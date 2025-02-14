package k8s

import (
	"sort"
	"strconv"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

func addAnnotation(annotations map[string]string, name string, data any) {
	const maxAnnotationLen = 63
	formattedKey := "hash.operator.tigera.io/" + name
	if len(formattedKey) > maxAnnotationLen {
		formattedKey = formattedKey[0:maxAnnotationLen]
	}

	// If there's a collision in key naming then we just append numbers until there's not a collision.
	for i := 1; ; i++ {
		if _, ok := annotations[formattedKey]; !ok {
			break
		}
		suffix := strconv.Itoa(i)
		formattedKey = formattedKey[0:len(formattedKey)-len(suffix)] + suffix
	}

	var hashedValue string
	switch typedData := data.(type) {
	case map[string]string:
		var annoteData []string
		for k, v := range typedData {
			annoteData = append(annoteData, k+rmeta.AnnotationHash(v))
		}
		sort.Strings(annoteData)
		hashedValue = rmeta.AnnotationHash(annoteData)
	case map[string][]byte:
		var annoteData []string
		for k, v := range typedData {
			annoteData = append(annoteData, k+rmeta.AnnotationHash(v))
		}
		sort.Strings(annoteData)
		hashedValue = rmeta.AnnotationHash(annoteData)
	default:
		hashedValue = rmeta.AnnotationHash(data)
	}

	annotations[formattedKey] = hashedValue
}
