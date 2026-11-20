package feed

import (
	"io"
	"os"
)

// osStderr is indirected so tests can capture the alert log.
var osStderr = func() io.Writer { return os.Stderr }
