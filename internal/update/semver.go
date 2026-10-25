package update

import (
	"regexp"
	"strconv"
	"strings"
)

// version is a parsed semantic version. Build metadata (+dirty, +incompatible) is dropped.
type version struct {
	num [3]int
	pre string
	ok  bool
}

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// pseudoRe matches the end of a Go pseudo-version's pre-release: a 14-digit UTC time and a 12-char
// commit hash (v0.0.0-20261024160549-dfc3ef737dc9, v1.2.4-0.20261024160549-dfc3ef737dc9).
var pseudoRe = regexp.MustCompile(`(?:^|\.)(\d{14})-[0-9a-f]{12}$`)

func parse(s string) version {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}
	}
	var v version
	for i := range v.num {
		v.num[i], _ = strconv.Atoi(m[i+1]) // a missing patch (nmap's 7.94) is 0
	}
	v.pre, v.ok = m[4], true
	return v
}

// pseudoTime is the commit time of a pseudo-version, or "" for a tag.
func (v version) pseudoTime() string {
	if m := pseudoRe.FindStringSubmatch(v.pre); m != nil {
		return m[1]
	}
	return ""
}

// IsRelease is true for a tagged version: parseable and not a pseudo-version.
func IsRelease(s string) bool {
	v := parse(s)
	return v.ok && v.pseudoTime() == ""
}

// Compare orders two versions: -1 when a is older than b, 0 when equal, 1 when newer. Anything that
// does not parse ("", "(devel)") is older than any version. A pseudo-version (an untagged commit) is
// older than any tag; two pseudo-versions are ordered by commit time.
func Compare(a, b string) int {
	va, vb := parse(a), parse(b)
	switch {
	case !va.ok || !vb.ok:
		return cmpBool(va.ok, vb.ok)
	}
	ta, tb := va.pseudoTime(), vb.pseudoTime()
	switch {
	case ta != "" && tb != "":
		return strings.Compare(ta, tb)
	case ta != "" || tb != "":
		return cmpBool(ta == "", tb == "")
	}
	for i := range va.num {
		if va.num[i] != vb.num[i] {
			return cmpInt(va.num[i], vb.num[i])
		}
	}
	return comparePre(va.pre, vb.pre)
}

// comparePre orders pre-releases per semver: none is newer than any; identifiers compare one by one,
// numbers numerically and below words; a shorter list that is a prefix is older.
func comparePre(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" || b == "" {
		return cmpBool(a == "", b == "")
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				return cmpInt(na, nb)
			}
		case ea == nil || eb == nil:
			return cmpBool(ea != nil, eb != nil)
		default:
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(pa), len(pb))
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cmpBool orders false before true.
func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	}
	return 1
}

var engineVersionRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// EngineVersion returns the first X.Y.Z (or X.Y, as nmap prints) in an engine's version output, or "".
func EngineVersion(out string) string {
	m := engineVersionRe.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	if m[3] == "" {
		return m[1] + "." + m[2]
	}
	return m[1] + "." + m[2] + "." + m[3]
}
