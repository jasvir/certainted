//go:build windows

package main

import "os"

// The control directory is inside this account's Windows LocalAppData cache.
// Windows ACLs, rather than FileMode owner bits, protect that profile path.
func controlOwnerOK(os.FileInfo) bool { return true }
