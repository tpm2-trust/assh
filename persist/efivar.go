package persist

// EFI variables: where a machine has no other place that survives a reboot
// (a read-only image), or none outside a boot image whose measurement an
// approval names. The variables written here are plain ones - non-volatile,
// boot service and runtime access, no authenticated write - so they hold
// nothing whose change would matter unchecked: aSSH's CA is checked by the
// TPM each time it signs, safearch's selection by the signed command line.

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/tpm2-trust/uefi/efivar"
)

// VarPrefix names an EFI variable wherever a file's path goes: "efi:NAME"
// (aSSH's vendor GUID) or "efi:NAME-GUID".
const VarPrefix = "efi:"

// VarGUID is the vendor GUID of aSSH's variables.
const VarGUID = "24415b90-39be-45c0-a9a3-d547ebe28ea0"

// varAttributes: non-volatile, boot service and runtime access.
const varAttributes = efivar.NonVolatile | efivar.BootServiceAccess | efivar.RuntimeAccess

// VarDir is where efivarfs is mounted; tests, and the assh command's
// ASSH_EFIVARS, point it elsewhere.
var VarDir = efivar.DefaultDir

// guidSuffix is a vendor GUID at the end of a variable's location.
var guidSuffix = regexp.MustCompile(`-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// IsVar reports whether location names an EFI variable ("efi:...").
func IsVar(location string) bool { return strings.HasPrefix(location, VarPrefix) }

// variable is location's variable: "efi:NAME" with aSSH's GUID,
// "efi:NAME-GUID" with that one. Names are narrower than efivarfs takes:
// letters, digits, _ and -.
func variable(location string) (string, efivar.GUID, error) {
	name := strings.TrimPrefix(location, VarPrefix)
	guid := VarGUID
	if m := guidSuffix.FindStringSubmatch(strings.ToLower(name)); m != nil {
		guid = m[1]
		name = name[:len(name)-len(m[0])]
	}
	if name == "" || len(name) > 64 {
		return "", efivar.GUID{}, fmt.Errorf("%s: not an EFI variable name", location)
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return "", efivar.GUID{}, fmt.Errorf("%s: not an EFI variable name (letters, digits, _ and -)", location)
		}
	}
	g, err := efivar.ParseGUID(guid)
	return name, g, err
}

// store is efivarfs at VarDir: one whole write, the immutable mark lifted
// for a write or removal and put back, also after a failure.
func store() efivar.Store { return efivar.Store{Dir: VarDir} }

// VarPath is the efivarfs file of location's variable.
func VarPath(location string) (string, error) {
	name, guid, err := variable(location)
	if err != nil {
		return "", err
	}
	return store().Path(name, guid)
}

// ReadVar is the variable's contents, whatever its attributes; an error
// that os.IsNotExist knows when there is none.
func ReadVar(location string) ([]byte, error) {
	name, guid, err := variable(location)
	if err != nil {
		return nil, err
	}
	_, data, err := store().Read(name, guid)
	return data, err
}

// WriteVar replaces the variable's contents, in one write: the firmware
// takes the whole variable or none of it, and the old one stays until the
// new one is there. An empty value is refused (efivarfs would remove the
// variable): use RemoveVar.
func WriteVar(location string, data []byte) error {
	name, guid, err := variable(location)
	if err != nil {
		return err
	}
	return store().Write(name, guid, varAttributes, data)
}

// RemoveVar removes the variable. It reports whether there was one.
func RemoveVar(location string) (bool, error) {
	name, guid, err := variable(location)
	if err != nil {
		return false, err
	}
	if err := store().Remove(name, guid); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
