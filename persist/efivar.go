package persist

// EFI variables: where a machine has no other place that survives a reboot
// (a read-only image), or none outside a boot image whose measurement an
// approval names. The variables written here are plain ones - non-volatile,
// boot service and runtime access, no authenticated write - so they hold
// nothing whose change would matter unchecked: aSSH's CA is checked by the
// TPM each time it signs, safearch's selection by the signed command line.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// VarPrefix names an EFI variable wherever a file's path goes: "efi:NAME"
// (aSSH's vendor GUID) or "efi:NAME-GUID".
const VarPrefix = "efi:"

// VarGUID is the vendor GUID of aSSH's variables.
const VarGUID = "24415b90-39be-45c0-a9a3-d547ebe28ea0"

// varAttributes: non-volatile, boot service and runtime access.
const varAttributes = 0x7

// fsImmutable is FS_IMMUTABLE_FL of linux/fs.h.
const fsImmutable = 0x10

// efivarfsMagic is EFIVARFS_MAGIC of linux/magic.h.
const efivarfsMagic = 0xde5e81e4

// VarDir is where efivarfs is mounted; tests, and the assh command's
// ASSH_EFIVARS, point it elsewhere.
var VarDir = "/sys/firmware/efi/efivars"

// guidSuffix is a vendor GUID at the end of a variable's location.
var guidSuffix = regexp.MustCompile(`-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// IsVar reports whether location names an EFI variable ("efi:...").
func IsVar(location string) bool { return strings.HasPrefix(location, VarPrefix) }

// VarPath is the efivarfs file of location's variable: "efi:NAME" with
// aSSH's GUID, "efi:NAME-GUID" with that one.
func VarPath(location string) (string, error) {
	name := strings.TrimPrefix(location, VarPrefix)
	guid := VarGUID
	if m := guidSuffix.FindStringSubmatch(strings.ToLower(name)); m != nil {
		guid = m[1]
		name = name[:len(name)-len(m[0])]
	}
	if name == "" || len(name) > 64 {
		return "", fmt.Errorf("%s: not an EFI variable name", location)
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return "", fmt.Errorf("%s: not an EFI variable name (letters, digits, _ and -)", location)
		}
	}
	return filepath.Join(VarDir, name+"-"+guid), nil
}

// ReadVar is the variable's contents, without its attributes; an error
// that os.IsNotExist knows when there is none.
func ReadVar(location string) ([]byte, error) {
	path, err := VarPath(location)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("%s: no attributes", path)
	}
	return b[4:], nil
}

// WriteVar replaces the variable's contents, in one write: the firmware
// takes the whole variable or none of it, and the old one stays until the
// new one is there. efivarfs marks a variable immutable against an
// accidental rm; the mark is lifted for the write and put back.
func WriteVar(location string, data []byte) error {
	path, err := VarPath(location)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return fmt.Errorf("no efivarfs at %s: %w", filepath.Dir(path), err)
	}
	immutable, err := setImmutable(path, false)
	if err != nil {
		return err
	}
	b := binary.LittleEndian.AppendUint32(nil, varAttributes)
	b = append(b, data...)
	// efivarfs replaces the variable with each write, as libefivar
	// writes it: no truncation. Anywhere else (a test's directory) the
	// file is truncated to the same effect.
	flags := os.O_WRONLY | os.O_CREATE
	var fs unix.Statfs_t
	if unix.Statfs(filepath.Dir(path), &fs) != nil || fs.Type != efivarfsMagic {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("writing %s (%d bytes): %w", path, len(b), werr)
	}
	if cerr != nil {
		return cerr
	}
	if immutable {
		_, err = setImmutable(path, true)
	}
	return err
}

// RemoveVar removes the variable, lifting the immutable mark first. It
// reports whether there was one.
func RemoveVar(location string) (bool, error) {
	path, err := VarPath(location)
	if err != nil {
		return false, err
	}
	if _, err := setImmutable(path, false); err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// setImmutable sets or clears path's immutable flag and reports whether it
// was set. A file that is not there, or a file system without the flags,
// has none.
func setImmutable(path string, on bool) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	flags, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	was := flags&fsImmutable != 0
	want := flags &^ fsImmutable
	if on {
		want |= fsImmutable
	}
	if want != flags {
		if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(want)); err != nil {
			return was, fmt.Errorf("%s: the immutable flag: %w", path, err)
		}
	}
	return was, nil
}
