package utils

import (
	"path/filepath"

	"github.com/google/uuid"
)

func GenUniquePath(name string) string {
	ext := filepath.Ext(name)
	path := "assets/" + uuid.New().String() + ext
	return path
}
