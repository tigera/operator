package render

func Bool(b bool) *bool {
	return &b
}

func Int64(i int64) *int64 {
	return &i
}

// Count the number of true booleans among the input arguments.
func CountTrues(bools ...bool) int8 {
	var sum int8 = 0
	for _, b := range bools {
		if b {
			sum++
		}
	}
	return sum
}
