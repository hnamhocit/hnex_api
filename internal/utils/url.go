package utils

import "os"

func GetDownloadURL(path string) string {
	url := os.Getenv("BASE_URL") + "/" + path
	return url
}

func ExtractDownloadURL(url string) string {
	return url[len(os.Getenv("BASE_URL"))+1:]
}
