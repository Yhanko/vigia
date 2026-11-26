// Package migrations embeds versioned SQL migrations for goose.
package migrations

import "embed"

// FS contains all SQL migration files bundled into the Vigia binary.
//
//go:embed *.sql
var FS embed.FS
