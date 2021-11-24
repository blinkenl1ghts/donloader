# donLoader

WARNING: This is WIP, barely anything was tested properly. Use at your own risk.

## Description
donLoader is a shellcode loader creation tool that uses donut to convert executable payloads into shellcode to evade detection on disk. 

## Install
```
git clone https://github.com/blinkenl1ghts/donloader
cd donloader
go install mvdan.cc/garble@latest
sudo apt install upx
GO111MODULE=off go get -u golang.org/x/sys/...
GO111MODULE=off go get -u github.com/C-Sto/BananaPhone
GO111MODULE=off go get -u github.com/Binject/debug
GO111MODULE=off go get -u github.com/awgh/rawreader
go build -o "bin/donloader" .
```

## Usage
```
Usage of ./donloader:
  -arg string
    	Arguments passed to donut payload
  -bypass int
    	donut: Bypass AMSI/WLDP 1=skip, 2=abort on fail, 3=continue on fail (default 3)
  -compress int
    	donut: Compress payload 1=disable, 2=LZNT1, 3=Xpress, 4=Xpress Huffman (default 1)
  -custom
    	-tpl specifies custom template source instead of using built in templates
  -debug
    	Generate debug builds
  -entropy int
    	donut: Entropy 1=disable, 2=use random names, 3=random names + symmetric encryption (default 1)
  -ex int
    	donut: Exit method 1=exit thread, 2=exit process (default 1)
  -g	Use garble to compile and obfuscate loader.
  -no-donut
    	Treats -payload as shellcode, does not use donut to convert it
  -payload string
    	EXE/DLL/.NET payload to convert into donut shellcode
  -tpl string
    	Loader template to use (default "sc_ct")
  -upx
    	Pack final binary with upx.
  -url string
    	donut: URL hosting payload for HTTP delivery
```

Exmples:
- CreateThread current process injection via direct system calls (BananaPhone), obfuscated with garble and with additonal shellcode entropy option in donut.
```
./bin/donloader -g -entropy 3 -tpl bp_ct -payload calc.exe
```

## Templates
- sc_ct
  Inject shellcode into current process with CreateThread 
- sc_fiber
  Inject shellcode into current process via fibers 
- sc_crt
  Inject shellcode into another process via CreateRemoteThread (hardcoded explorer.exe at the moment)
- sc_ebapc
  Spawn notepad.exe and inject shellcode via QueueUserAPC. 
- sc_evasion_crt
  - Block DLL: hardcoded nonms (not allowing non-MS) 
  - PPID Spoofing
  - Shellcode injection via CreateRemoteThread
  - Heavily based on D00mFist's Go4aRun - https://github.com/D00MFist/Go4aRun
- sc_evasion_ebapc.go
  - Block DLL: hardcoded nonms (not allowing non-MS) 
  - PPID Spoofing
  - Shellcode injection via QueueUserAPC
  - Heavily based on D00mFist's Go4aRun - https://github.com/D00MFist/Go4aRun
- bp_ct
  - Shellcode injection via CreateThread using direct system calls 
  - Using C-Sto BananaPhone - https://github.com/C-Sto/BananaPhone

## Reference
This project is based on:
- https://github.com/C-Sto/BananaPhone
- https://github.com/D00MFist/Go4aRun
- https://github.com/Ne0nd0g/go-shellcode
- https://github.com/sh4hin/GoPurple
- https://github.com/Binject/go-donut
- https://github.com/TheWover/donut
- https://github.com/BishopFox/sliver
- https://github.com/xct/morbol
