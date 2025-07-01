package utils

import (
	"fmt"

	"github.com/nyaruka/phonenumbers"
)

func FormatPhoneInternational(phone, countryCode string) (string, error) {
	num, err := phonenumbers.Parse(phone, countryCode)
	if err != nil {
		return "", err
	}

	if !phonenumbers.IsValidNumber(num) {
		return "", fmt.Errorf("invalid phone number")
	}

	return phonenumbers.Format(num, phonenumbers.INTERNATIONAL), nil
}
