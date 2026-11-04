// Package icon is the SSH module's icon in core's UI, the factory's and the
// channel's alike: a terminal window and its prompt. Line art, so it reads
// light or dark; Light has heavier lines for light themes.
package icon

import _ "embed"

// Dark is the icon for dark themes.
//
//go:embed icon.svg
var Dark string

// Light is the icon for light themes.
//
//go:embed icon-light.svg
var Light string
