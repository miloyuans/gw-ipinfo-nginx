package routesets

func loadV2File(path string) ([]passRoute, error) {
	return loadV1File(path)
}
