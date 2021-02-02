package render

func Bool(b bool) *bool {
	return &b
}

func Int64(i int64) *int64 {
	return &i
}

func BoolToInt(b bool) int8 {
	if b {
		return 1
	}
	return 0
}
