// SPDX-Licence-Identifier: MIT
package lowlevel

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func getSeccompProcValue(pid int) (int, error) {
	status_file_path := fmt.Sprintf("/proc/%d/status", pid)
	status_file, err := os.Open(status_file_path)
	if err != nil {
		return 0, err
	}
	defer status_file.Close()
	scanner := bufio.NewScanner(status_file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Seccomp:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
			seccomp_value, err := strconv.Atoi(value)
			if err != nil {
				return 0, err
			}
			return seccomp_value, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("No Seccomp value in status")
}

func TestSeccompGetActionAvail(t *testing.T) {
	if !SeccompGetActionAvail(SECCOMP_RET_ALLOW) {
		t.Error("Get Action ALLOW not here")
	}
	if SeccompGetActionAvail(1) {
		t.Error("Get Action 1 here and shouldn't")
	}
}

func TestSeccompGetNotifSize(t *testing.T) {
	sizes, err := SeccompGetNotifSizes()
	if err != nil {
		t.Errorf("Error on seccomp call: %v", err)
	}
	if sizes.SeccompData == 0 || sizes.SeccompNotif == 0 || sizes.SeccompNotifResp == 0 {
		t.Error("All sizes are 0")
	}
	// Cannot make any other assertion on Notif sizes as they
	// depends on kernel version
}

func TestNoNewPrivs(t *testing.T) {
	skipc := make(chan bool, 1)
	skip := func() {
		skipc <- true
		runtime.Goexit()
	}

	go func() {
		// This test uses prctl to modify the calling thread, so run it on its own
		// throwaway thread and do not unlock it when the goroutine exits.
		runtime.LockOSThread()
		defer close(skipc)

		err := NoNewPrivs()
		if err != nil {
			t.Logf("Prctl: %v, skipping test", err)
			skip()
		}

		v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
		if err != nil {
			t.Errorf("failed to perform prctl: %v", err)
		}
		if v != 1 {
			t.Errorf("unexpected return from prctl; got %v, expected %v", v, 1)
		}
	}()

	if <-skipc {
		t.SkipNow()
	}
}

func TestSeccompInsertFilter(t *testing.T) {
	skipc := make(chan bool, 1)
	skip := func() {
		skipc <- true
		runtime.Goexit()
	}

	go func() {
		// This test uses prctl to modify the calling thread, so run it on its own
		// throwaway thread and do not unlock it when the goroutine exits.
		runtime.LockOSThread()
		defer close(skipc)

		instructions, _ := bpf.Assemble([]bpf.Instruction{
			bpf.RetConstant{Val: SECCOMP_RET_ALLOW},
		})
		err := NoNewPrivs()
		if err != nil {
			t.Logf("Prctl: %v, skipping test", err)
			skip()
		}
		err = NoNewPrivs()
		if err != nil {
			t.Logf("Prctl: %v, skipping test", err)
			skip()
		}
		_, err = SeccompSetModeFilter(instructions, 0)
		if err != nil {
			t.Logf("Seccomp: %v, skipping test", err)
			skip()
		}

		v, err := getSeccompProcValue(unix.Gettid())
		if err != nil {
			t.Errorf("failed to perform seccomp: %v", err)
		}
		if v != 2 {
			t.Errorf("unexpected return from seccomp; got %v, expected %v", v, 2)
		}
	}()

	if <-skipc {
		t.SkipNow()
	}
}
