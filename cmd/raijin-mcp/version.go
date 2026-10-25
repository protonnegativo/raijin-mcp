package main

import "runtime/debug"

// version is the release this binary was built from: the module version for `go install ...@vX.Y.Z`
// (or @latest), else "dev" with the VCS revision a local `go build` records.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	return versionFrom(info)
}

// A build from a checkout records vcs.* settings (and since Go 1.24 a pseudo Main.Version), so the
// module version is trusted only when there are none, as for a module downloaded by `go install`.
func versionFrom(info *debug.BuildInfo) string {
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if v := info.Main.Version; rev == "" && v != "" && v != "(devel)" {
		return v
	}
	v := "dev"
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		v += "-" + rev
	}
	if dirty {
		v += "+dirty"
	}
	return v
}
