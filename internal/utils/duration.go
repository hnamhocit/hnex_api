package utils

import (
	"encoding/json"
	"time"
)

type DurationString time.Duration

func (d *DurationString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = DurationString(parsed)
	return nil
}

func (d DurationString) ToDuration() time.Duration {
	return time.Duration(d)
}
