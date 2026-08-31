package azpim

import (
	"fmt"
	"strings"
	"time"
)

// parseDuration turns a duration into the ISO 8601 form Graph expects.
//
// Graph speaks ISO 8601 ("PT8H"), which is awkward to type, so a Go duration
// ("8h", "1h30m") is accepted and converted. A value already in ISO 8601 form
// is passed through, both so that scripts written against the raw API keep
// working and so that units Go cannot express, such as days, stay reachable.
func parseDuration(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("duration is empty")
	}

	if strings.HasPrefix(strings.ToUpper(value), "P") {
		return strings.ToUpper(value), nil
	}

	parsed, err := time.ParseDuration(value)

	if err != nil {
		return "", fmt.Errorf("invalid duration %q: it must be a Go duration such as 8h, or ISO 8601 such as PT8H", value)
	}

	if parsed <= 0 {
		return "", fmt.Errorf("duration %q must be positive", value)
	}

	return isoDuration(parsed), nil
}

// isoDuration renders a positive duration as an ISO 8601 time span.
//
// Sub-second precision is dropped: PIM policies are expressed in minutes and
// hours, and a fractional second in the request only invites a rounding
// argument with the service.
func isoDuration(d time.Duration) string {
	d = d.Round(time.Second)

	hours := int64(d / time.Hour)
	minutes := int64(d%time.Hour) / int64(time.Minute)
	seconds := int64(d%time.Minute) / int64(time.Second)

	out := &strings.Builder{}
	out.WriteString("PT")

	if hours > 0 {
		fmt.Fprintf(out, "%dH", hours)
	}

	if minutes > 0 {
		fmt.Fprintf(out, "%dM", minutes)
	}

	// Without this a duration under a minute would render as a bare "PT".
	if seconds > 0 || out.String() == "PT" {
		fmt.Fprintf(out, "%dS", seconds)
	}

	return out.String()
}
