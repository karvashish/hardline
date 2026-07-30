// Package schema embeds the generated JSON schemas so a released binary can
// validate a profile without the source tree, and so a schema on disk cannot be
// weakened to admit a profile the signer never validated.
package schema

import "embed"

//go:embed profile.schema.json action-file.schema.json
var FS embed.FS
