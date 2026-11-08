// Package version holds the build's identity, stamped by the Makefile's
// -ldflags or read from the build information when none were given.
package version

import (
	"fmt"
	"runtime/debug"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// init fills what -ldflags left unset from the build info: `go install
// module@version` stamps the module version, a build in a checkout the commit.
func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := info.Main.Version; Version == "dev" && v != "" && v != "(devel)" {
		Version = v
	}
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision" && GitCommit == "unknown":
			GitCommit = s.Value[:min(len(s.Value), 12)]
		case s.Key == "vcs.time" && BuildTime == "unknown":
			BuildTime = s.Value
		}
	}
}

func String() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildTime)
}
