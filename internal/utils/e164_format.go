package utils

import (
	"strings"

	"github.com/nyaruka/phonenumbers"
)

func E164Format(numberToParse, defaultRegion string) (string, error) {
	defaultRegion = strings.ToUpper(strings.TrimSpace(defaultRegion))

	phone, err := phonenumbers.Parse(numberToParse, defaultRegion)
	if err != nil {
		return "", err
	}

	return phonenumbers.Format(phone, phonenumbers.E164), nil
}
