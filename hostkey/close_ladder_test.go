package hostkey

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// faultyTPM is a real TPM with commands refused, or with PCR_Event sent to
// another PCR: the TPM answers success and PCR 15 does not move. Everything else
// goes through, so what a step leaves behind is the TPM's own doing.
type faultyTPM struct {
	transport.TPM
	refuse   func(cc tpm2.TPMCC, handle uint32) bool
	redirect bool
	dead     bool
}

func (f *faultyTPM) Send(cmd []byte) ([]byte, error) {
	if f.dead {
		return nil, errors.New("the device does not answer")
	}
	cc := tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:]))
	var handle uint32
	if len(cmd) >= 14 {
		handle = binary.BigEndian.Uint32(cmd[10:])
	}
	if f.refuse != nil && f.refuse(cc, handle) {
		rsp := binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMSTNoSessions))
		rsp = binary.BigEndian.AppendUint32(rsp, 10)
		return binary.BigEndian.AppendUint32(rsp, uint32(tpm2.TPMRCBadAuth)), nil
	}
	if f.redirect && cc == tpm2.TPMCCPCREvent && handle == ClosePCR {
		cmd = bytes.Clone(cmd)
		binary.BigEndian.PutUint32(cmd[10:], 16)
	}
	return f.TPM.Send(cmd)
}

func refusesExtend(pcrs ...uint32) func(tpm2.TPMCC, uint32) bool {
	return func(cc tpm2.TPMCC, h uint32) bool {
		if cc != tpm2.TPMCCPCREvent {
			return false
		}
		for _, p := range pcrs {
			if h == p {
				return true
			}
		}
		return false
	}
}

func changeAuth(t *testing.T, tpm transport.TPM, h tpm2.TPMHandle) {
	t.Helper()
	if _, err := (tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{Handle: h, Auth: tpm2.PasswordAuth(nil)},
		NewAuth:    tpm2.TPM2BAuth{Buffer: []byte("not ours")},
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
}

func hierarchies(t *testing.T, tpm transport.TPM) Hierarchies {
	t.Helper()
	h, err := ReadHierarchies(tpm)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A CA open in this boot, certifying.
func openCA(t *testing.T, sw *swtpmtest.SWTPM, tpm transport.TPMCloser) (*CA, IssueOptions) {
	t.Helper()
	auth := authority(t)
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}})
	if err != nil {
		t.Fatal(err)
	}
	sw.Reboot(t)
	now, err := ca.ReadPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Approve(auth, 0, now); err != nil {
		t.Fatal(err)
	}
	opts := IssueOptions{Principals: []string{"host.example"}, Open: sw.Opener()}
	certified(t, tpm, ca, opts, 0)
	return ca, opts
}

// PCR 15 refuses: the hierarchies go, the CA and whatever else is under the
// owner stop answering, while what the boot still needs works - and a next boot
// has them back.
func TestCloseKillSwitch(t *testing.T) {
	for name, fault := range map[string]*faultyTPM{
		"the extend refused":      {refuse: refusesExtend(ClosePCR)},
		"the extend did not move": {redirect: true},
	} {
		t.Run(name, func(t *testing.T) {
			sw := swtpmtest.Start(t)
			tpm := sw.Open(t)
			ca, opts := openCA(t, sw, tpm)
			tpm = sw.Open(t)
			before, _ := ReadPCRs(tpm, SHA256, []int{ClosePCR})

			fault.TPM = tpm
			res, err := Close(fault)
			if err != nil || res.How != ClosedHierarchies || !res.Degraded() {
				t.Fatalf("the close: %+v %v", res, err)
			}
			if got := res.String(); !strings.Contains(got, "shEnable clear") || !strings.Contains(got, "phEnable clear") {
				t.Fatalf("what it says: %s", got)
			}
			if h := hierarchies(t, tpm); h.Storage || h.Endorsement || h.Platform {
				t.Fatalf("the hierarchies: %+v", h)
			}
			now, _ := ReadPCRs(tpm, SHA256, []int{ClosePCR})
			if !bytes.Equal(now[ClosePCR], before[ClosePCR]) {
				t.Fatal("PCR 15 moved")
			}
			// PCR 15 still holds the open value: the TPM refuses all the same.
			if open, err := ca.IsOpen(tpm); err != nil || !open {
				t.Fatalf("open: %v %v", open, err)
			}
			hk, err := Issue(tpm, ca, opts)
			if err != nil || hk.Temporary == nil || hk.Cert != nil {
				t.Fatalf("the CA after the kill switch: %+v %v", hk, err)
			}
			if _, err := createPrimary(tpm, tpm2.TPMRHOwner); err == nil {
				t.Fatal("a primary under the owner")
			}
			// What the boot still needs: a key under the NULL hierarchy (the
			// temporary one above), an extend.
			swtpmtest.Extend(t, tpm, 16, "still extends")
			// The owner cannot take it back, nor the platform with phEnable clear.
			if err := hierarchyOn(tpm, tpm2.TPMRHOwner, tpm2.TPMRHOwner); err == nil {
				t.Fatal("the owner set shEnable again")
			}
			if err := hierarchyOn(tpm, tpm2.TPMRHPlatform, tpm2.TPMRHOwner); err == nil {
				t.Fatal("the platform set shEnable again with phEnable clear")
			}
			// A close more is a close: it says the same.
			if res, err := Close(fault); err != nil || res.How != ClosedHierarchies {
				t.Fatalf("again: %+v %v", res, err)
			}
			sw.Reboot(t)
			tpm = sw.Open(t)
			if h := hierarchies(t, tpm); !h.Storage || !h.Endorsement || !h.Platform {
				t.Fatalf("the hierarchies at the next boot: %+v", h)
			}
			certified(t, tpm, ca, opts, 0)
		})
	}
}

// hierarchyOn is what must not work after the kill switch.
func hierarchyOn(t transport.TPM, auth, enable tpm2.TPMHandle) error {
	cmd := binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMSTSessions))
	cmd = binary.BigEndian.AppendUint32(cmd, 0)
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMCCHierarchyControl))
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(auth))
	cmd = binary.BigEndian.AppendUint32(cmd, 9)
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMRSPW))
	cmd = append(cmd, 0, 0, 0, 0, 0)
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(enable))
	cmd = append(cmd, 1)
	binary.BigEndian.PutUint32(cmd[2:], uint32(len(cmd)))
	rsp, err := t.Send(cmd)
	if err != nil {
		return err
	}
	if rc := binary.BigEndian.Uint32(rsp[6:]); rc != 0 {
		return tpm2.TPMRC(rc)
	}
	return nil
}

// A firmware that locked the platform: ehEnable and phEnable stay, which is said
// and is no failure.
func TestCloseKillSwitchPlatformLocked(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	changeAuth(t, tpm, tpm2.TPMRHPlatform)
	res, err := Close(&faultyTPM{TPM: tpm, refuse: refusesExtend(ClosePCR)})
	if err != nil || res.How != ClosedHierarchies {
		t.Fatalf("the close: %+v %v", res, err)
	}
	if got := res.String(); !strings.Contains(got, "ehEnable stays set") || !strings.Contains(got, "phEnable stays set") {
		t.Fatalf("what it says: %s", got)
	}
	if h := hierarchies(t, tpm); h.Storage || !h.Endorsement || !h.Platform {
		t.Fatalf("the hierarchies: %+v", h)
	}
}

// The platform not locked and the owner with a password: the platform clears
// shEnable.
func TestCloseKillSwitchOwnerPassword(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	changeAuth(t, tpm, tpm2.TPMRHOwner)
	res, err := Close(&faultyTPM{TPM: tpm, refuse: refusesExtend(ClosePCR)})
	if err != nil || res.How != ClosedHierarchies {
		t.Fatalf("the close: %+v %v", res, err)
	}
	if !strings.Contains(res.String(), "the owner refused") {
		t.Fatalf("what it says: %s", res)
	}
}

// Owner and platform with passwords: PCR 7 moves, which the CA's slot reads.
func TestCloseFallsBackToPCR7(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	ca, opts := openCA(t, sw, tpm)
	tpm = sw.Open(t)
	changeAuth(t, tpm, tpm2.TPMRHOwner)
	changeAuth(t, tpm, tpm2.TPMRHPlatform)
	before, _ := ReadPCRs(tpm, SHA256, []int{7, ClosePCR})
	res, err := Close(&faultyTPM{TPM: tpm, refuse: refusesExtend(ClosePCR)})
	if err != nil || res.How != ClosedPCR7 || !res.Degraded() {
		t.Fatalf("the close: %+v %v", res, err)
	}
	now, _ := ReadPCRs(tpm, SHA256, []int{7, ClosePCR})
	if bytes.Equal(now[7], before[7]) || !bytes.Equal(now[ClosePCR], before[ClosePCR]) {
		t.Fatalf("PCR 7 %x -> %x, PCR 15 %x -> %x", before[7], now[7], before[ClosePCR], now[ClosePCR])
	}
	if h := hierarchies(t, tpm); !h.Storage {
		t.Fatalf("the hierarchies: %+v", h)
	}
	temporary(t, tpm, ca, opts)
}

// Every step refused: a failure, which says that the TPM answers; a device that
// does not answer says so too.
func TestCloseFailsEveryWay(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	changeAuth(t, tpm, tpm2.TPMRHOwner)
	changeAuth(t, tpm, tpm2.TPMRHPlatform)
	_, err := Close(&faultyTPM{TPM: tpm, refuse: refusesExtend(ClosePCR, closeFallbackPCR)})
	var ce *CloseError
	if !errors.As(err, &ce) || !ce.Answers || !strings.Contains(err.Error(), "the TPM answers and refuses") {
		t.Fatalf("all refused: %v", err)
	}
	_, err = Close(&faultyTPM{TPM: tpm, dead: true})
	if !errors.As(err, &ce) || ce.Answers || !strings.Contains(err.Error(), "the TPM does not answer") {
		t.Fatalf("a dead device: %v", err)
	}
}

// One refused extend is tried once more: no degraded close for a passing fault.
func TestCloseTriesOnceMore(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	refused := 0
	res, err := Close(&faultyTPM{TPM: tpm, refuse: func(cc tpm2.TPMCC, h uint32) bool {
		if cc == tpm2.TPMCCPCREvent && refused == 0 {
			refused++
			return true
		}
		return false
	}})
	if err != nil || res.How != ClosedPCR15 || res.Degraded() {
		t.Fatalf("the close: %+v %v", res, err)
	}
	if h := hierarchies(t, tpm); !h.Storage {
		t.Fatalf("the hierarchies: %+v", h)
	}
}

// A suspend to RAM keeps what the close did: PCR 15 and the hierarchies alike
// (TPM2_Startup(STATE); only Startup(CLEAR) sets them again).
func TestCloseAcrossSuspend(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	if res, err := Close(&faultyTPM{TPM: tpm, refuse: refusesExtend(ClosePCR)}); err != nil || res.How != ClosedHierarchies {
		t.Fatalf("the close: %+v %v", res, err)
	}
	swtpmtest.Extend(t, tpm, ClosePCR, "moved")
	want, _ := ReadPCRs(tpm, SHA256, []int{ClosePCR})
	tpm.Close()
	sw.Suspend(t)
	tpm = sw.Open(t)
	// Every TPM2_Startup sets phEnable; the two others stay clear.
	if h := hierarchies(t, tpm); h.Storage || h.Endorsement || !h.Platform {
		t.Fatalf("the hierarchies after the resume: %+v", h)
	}
	// The platform is on again, and may not set shEnable.
	if err := hierarchyOn(tpm, tpm2.TPMRHPlatform, tpm2.TPMRHOwner); err == nil {
		t.Fatal("after the resume, the platform's empty authorization set shEnable again")
	}
	if got, _ := ReadPCRs(tpm, SHA256, []int{ClosePCR}); !bytes.Equal(got[ClosePCR], want[ClosePCR]) {
		t.Fatalf("PCR 15 after the resume: %x, want %x", got[ClosePCR], want[ClosePCR])
	}
}
