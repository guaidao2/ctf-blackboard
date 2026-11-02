package client

import (
	"embed"
	"io/fs"
)

//go:embed web
var embeddedWeb embed.FS

func webRoot() fs.FS {
	sub, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		panic(err)
	}
	return sub
}
