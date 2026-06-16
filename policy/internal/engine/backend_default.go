package engine

import "github.com/usetero/policy-go/policy/regexbackend"

// defaultBackend is the backend used when the caller supplies none. The core
// module references no implementation, so it is nil in production: callers must
// provide a backend via policy.WithRegexBackend (e.g. the teroscan or hyperscan
// module). Compiling any regex pattern without one returns an error (see
// compileGroup). Core's own tests set this to an in-package fake via init.
var defaultBackend regexbackend.Backend
