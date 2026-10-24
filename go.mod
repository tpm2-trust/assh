module github.com/tpm2-trust/assh

go 1.26.0

require (
	github.com/google/go-tpm v0.9.9-0.20261001171150-36f205946d7e
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
)

// TPM2_NV_ChangeAuth, TPM2_DictionaryAttackLockReset and the response HMAC
// of a command that changes an authorization value, until they are released
// upstream. A replace does not reach a module that uses assh: only tpmadmin
// needs them, and hostkey does not import it.
replace github.com/google/go-tpm => github.com/mrwiora/go-tpm v0.0.0-20261024135940-85890fca3a47
