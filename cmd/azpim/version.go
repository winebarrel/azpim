package main

import "runtime/debug"

// resolveVersion returns the version to show for --version.
//
// GoReleaser stamps one in with ldflags at release time. A build made any
// other way has none, so what the Go toolchain embedded is used instead: the
// commit for a build from a checkout, or the module version for an install at
// a tag.
func resolveVersion(version string) string {
	if version != "" {
		return version
	}

	info, ok := debug.ReadBuildInfo()

	if !ok {
		return ""
	}

	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}

	return info.Main.Version
}
