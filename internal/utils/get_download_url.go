package utils

import "os"

func GetDownloadURL(path string) string {
	url := os.Getenv("BASE_URL") + "/" + path
	return url
}
