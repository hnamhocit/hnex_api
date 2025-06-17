package utils

import (
	"log"
	"regexp"
	"strings"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

var diacriticsRemover = transform.Chain(norm.NFD, transform.RemoveFunc(func(r rune) bool {
	return r >= '\u0300' && r <= '\u036F'
}), norm.NFC)

func toASCII(s string) string {
	result, _, err := transform.String(diacriticsRemover, s)
	if err != nil {
		log.Printf("Error transforming string to ASCII: %v", err)
		return s
	}
	return result
}

func Slugify(s string) string {
	s = toASCII(s)

	s = strings.ToLower(s)

	reg := regexp.MustCompile(`[^\p{L}\p{N}]+`)
	s = reg.ReplaceAllString(s, "-")

	s = strings.Trim(s, "-")

	if s == "" {
		return "untitled"
	}

	return s
}
