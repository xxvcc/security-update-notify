package backend

import (
	"fmt"
	"strings"
)

type rpmEVR struct {
	epoch   string
	version string
	release string
}

func parseRPMEVR(value string) (rpmEVR, error) {
	var out rpmEVR
	if value == "" {
		return out, fmt.Errorf("empty RPM EVR")
	}
	out.epoch = "0"
	versionRelease := value
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		if colon == 0 || colon == len(value)-1 || strings.IndexByte(value[colon+1:], ':') >= 0 {
			return out, fmt.Errorf("invalid RPM epoch in %q", value)
		}
		out.epoch = value[:colon]
		versionRelease = value[colon+1:]
		for i := range out.epoch {
			if !asciiDigit(out.epoch[i]) {
				return rpmEVR{}, fmt.Errorf("invalid RPM epoch in %q", value)
			}
		}
	}
	dash := strings.LastIndexByte(versionRelease, '-')
	if dash <= 0 || dash == len(versionRelease)-1 {
		return rpmEVR{}, fmt.Errorf("invalid RPM version-release in %q", value)
	}
	out.version = versionRelease[:dash]
	out.release = versionRelease[dash+1:]
	if !validRPMVersionComponent(out.version) || !validRPMVersionComponent(out.release) {
		return rpmEVR{}, fmt.Errorf("invalid RPM version-release in %q", value)
	}
	return out, nil
}

func validRPMVersionComponent(value string) bool {
	hasAlnum := false
	for i := range value {
		c := value[i]
		if c < 0x21 || c > 0x7e || c == ':' || c == '-' {
			return false
		}
		hasAlnum = hasAlnum || asciiAlnum(c)
	}
	return hasAlnum
}

func rpmEVRCompare(left, right string) (int, error) {
	a, err := parseRPMEVR(left)
	if err != nil {
		return 0, err
	}
	b, err := parseRPMEVR(right)
	if err != nil {
		return 0, err
	}
	if result := compareNumericStrings(a.epoch, b.epoch); result != 0 {
		return result, nil
	}
	if result := rpmVersionCompare(a.version, b.version); result != 0 {
		return result, nil
	}
	return rpmVersionCompare(a.release, b.release), nil
}

// rpmVersionCompare mirrors rpmvercmp's ASCII segment ordering, including the special pre-release
// tilde and post-release snapshot caret operators. Inputs have already passed parseRPMEVR validation.
func rpmVersionCompare(left, right string) int {
	if left == right {
		return 0
	}
	i, j := 0, 0
	for i < len(left) || j < len(right) {
		for i < len(left) && !asciiAlnum(left[i]) && left[i] != '~' && left[i] != '^' {
			i++
		}
		for j < len(right) && !asciiAlnum(right[j]) && right[j] != '~' && right[j] != '^' {
			j++
		}

		leftTilde := i < len(left) && left[i] == '~'
		rightTilde := j < len(right) && right[j] == '~'
		if leftTilde || rightTilde {
			if !leftTilde {
				return 1
			}
			if !rightTilde {
				return -1
			}
			i++
			j++
			continue
		}

		leftCaret := i < len(left) && left[i] == '^'
		rightCaret := j < len(right) && right[j] == '^'
		if leftCaret || rightCaret {
			if i == len(left) {
				return -1
			}
			if j == len(right) {
				return 1
			}
			if !leftCaret {
				return 1
			}
			if !rightCaret {
				return -1
			}
			i++
			j++
			continue
		}

		if i == len(left) || j == len(right) {
			break
		}

		leftStart, rightStart := i, j
		numeric := asciiDigit(left[i])
		if numeric {
			for i < len(left) && asciiDigit(left[i]) {
				i++
			}
			for j < len(right) && asciiDigit(right[j]) {
				j++
			}
		} else {
			for i < len(left) && asciiAlpha(left[i]) {
				i++
			}
			for j < len(right) && asciiAlpha(right[j]) {
				j++
			}
		}

		if rightStart == j {
			if numeric {
				return 1
			}
			return -1
		}
		leftSegment, rightSegment := left[leftStart:i], right[rightStart:j]
		if numeric {
			leftSegment = strings.TrimLeft(leftSegment, "0")
			rightSegment = strings.TrimLeft(rightSegment, "0")
			if len(leftSegment) != len(rightSegment) {
				if len(leftSegment) > len(rightSegment) {
					return 1
				}
				return -1
			}
		}
		if leftSegment != rightSegment {
			if leftSegment > rightSegment {
				return 1
			}
			return -1
		}
	}
	if i == len(left) && j == len(right) {
		return 0
	}
	if i == len(left) {
		return -1
	}
	return 1
}

func compareNumericStrings(left, right string) int {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if len(left) != len(right) {
		if len(left) > len(right) {
			return 1
		}
		return -1
	}
	if left == right {
		return 0
	}
	if left > right {
		return 1
	}
	return -1
}

func asciiDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func asciiAlpha(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func asciiAlnum(c byte) bool {
	return asciiAlpha(c) || asciiDigit(c)
}
