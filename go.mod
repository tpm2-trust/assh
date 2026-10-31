module github.com/tpm2-trust/assh

go 1.26.0

require (
	github.com/google/go-tpm v0.9.9-0.20261030171821-c395998989d7
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
)

// EFI variables (efivarfs): the workspace's go-uefi-slim module, pinned as the
// submodule go-uefi-slim/. A replace does not reach a module that uses assh: each
// pins go-uefi-slim itself (tpm2-kira as its own submodule).
require github.com/tpm2-trust/go-uefi-slim v0.0.0

replace github.com/tpm2-trust/go-uefi-slim => ./go-uefi-slim
