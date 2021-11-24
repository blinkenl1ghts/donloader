package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

const (
	GOOS        = "windows"
	GOARCH      = "amd64"
	GO111MODULE = "off"
	ldFlags     = "-H=windowsgui -s -w"
)

func goBuild(srcPath string) error {
	args := []string{
		"build",
		"-ldflags",
		ldFlags,
		srcPath,
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, []string{
		fmt.Sprintf("GOOS=%s", GOOS),
		fmt.Sprintf("GOARCH=%s", GOARCH),
		fmt.Sprintf("GO111MODULE=%s", GO111MODULE),
	}...) //weird hacks ¯\_(ツ)_/¯
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		fmt.Println(stderr.String())
		return err
	}
	return nil
}

// use garble (https://github.com/burrowers/garble) to obfuscate binaries
// for some reason this more detections than normal go compiler ???
func garbleBuild(srcPath string) error {
	args := []string{
		"-literals",
		"-tiny",
		"build",
		"-ldflags",
		ldFlags,
		srcPath,
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cmd := exec.Command("garble", args...)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, []string{
		fmt.Sprintf("GOOS=%s", GOOS),
		fmt.Sprintf("GOARCH=%s", GOARCH),
		fmt.Sprintf("GO111MODULE=%s", GO111MODULE),
	}...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		fmt.Println(stderr.String())
		return err
	}
	return nil
}

func upx(binPath string) error {
	args := []string{
		"--brute",
		binPath,
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cmd := exec.Command("upx", args...)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		fmt.Println(stderr.String())
		return err
	}
	return nil
}
