// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/davecgh/go-spew/spew"
	"github.com/fdurand/wireguard-go/device"
	"github.com/fdurand/wireguard-go/ipc"
	"github.com/fdurand/wireguard-go/tun"
	"github.com/fdurand/wireguard-go/ztn/api"
	"github.com/fdurand/wireguard-go/ztn/hole"
	"github.com/fdurand/wireguard-go/ztn/profile"
	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"

	"net/http"
	_ "net/http/pprof"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

var ENV_ID = sharedutils.EnvOrDefault("ID", "")

var logger *device.Logger

var ctx = context.Background()

func printUsage() {
	fmt.Printf("usage:\n")
	fmt.Printf("%s [-f/--foreground] INTERFACE-NAME\n", os.Args[0])
}

func warning() {
	if runtime.GOOS != "linux" || os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
		return
	}

	fmt.Fprintln(os.Stderr, "┌───────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                   │")
	fmt.Fprintln(os.Stderr, "│   Running this software on Linux is unnecessary,  │")
	fmt.Fprintln(os.Stderr, "│   because the Linux kernel has built-in first     │")
	fmt.Fprintln(os.Stderr, "│   class support for WireGuard, which will be      │")
	fmt.Fprintln(os.Stderr, "│   faster, slicker, and better integrated. For     │")
	fmt.Fprintln(os.Stderr, "│   information on installing the kernel module,    │")
	fmt.Fprintln(os.Stderr, "│   please visit: <https://wireguard.com/install>.  │")
	fmt.Fprintln(os.Stderr, "│                                                   │")
	fmt.Fprintln(os.Stderr, "└───────────────────────────────────────────────────┘")
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("wireguard-go v%s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <Jason@zx2c4.com>.\n", device.WireGuardGoVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

	var foreground bool
	var interfaceName string
	if len(os.Args) < 2 || len(os.Args) > 3 {
		printUsage()
		return
	}

	switch os.Args[1] {

	case "-f", "--foreground":
		foreground = true
		if len(os.Args) != 3 {
			printUsage()
			return
		}
		interfaceName = os.Args[2]

	default:
		foreground = false
		if len(os.Args) != 2 {
			printUsage()
			return
		}
		interfaceName = os.Args[1]
	}

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "debug":
			return device.LogLevelDebug
		case "info":
			return device.LogLevelInfo
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelInfo
	}()

	// open TUN device (or use supplied fd)

	tun, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = syscall.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger = device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)

	logger.Debug.Println("Debug log enabled")

	if err != nil {
		logger.Error.Println("Failed to create TUN device:", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()

	if err != nil {
		logger.Error.Println("UAPI listen error:", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tun.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Error.Println("Failed to determine executable:", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Error.Println("Failed to daemonize:", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	device := device.NewDevice(tun, logger)

	logger.Info.Println("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Error.Println("Failed to listen on uapi socket:", err)
		os.Exit(ExitSetupFailed)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Info.Println("UAPI listener started")

	privateKey, publicKey := getKeys()

	profile := profile.Profile{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey[:]),
	}
	profile.FillProfileFromServer()

	profile.SetupWireguard(device, interfaceName)

	for _, peerID := range profile.AllowedPeers {
		startPeer(device, profile, peerID)
	}

	go listenEvents(device, profile)

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// wait for program to terminate

	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Info.Println("Shutting down")
}

//TODO: save these and reuse them after a restart
func getKeys() ([32]byte, [32]byte) {
	authFile := "auth.json"

	auth := struct {
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
	}{}

	if _, statErr := os.Stat(authFile); statErr == nil {
		f, err := os.Open(authFile)
		if err != nil {
			panic("Unable to open " + authFile + ": " + err.Error())
		}
		defer f.Close()

		err = json.NewDecoder(f).Decode(&auth)
		sharedutils.CheckError(err)
		priv, err := remoteclients.B64KeyToBytes(auth.PrivateKey)
		sharedutils.CheckError(err)
		pub, err := remoteclients.B64KeyToBytes(auth.PublicKey)
		sharedutils.CheckError(err)
		return priv, pub
	}
	f, err := os.Create(authFile)
	if err != nil {
		panic("Unable to create " + authFile + ": " + err.Error())
	}
	defer f.Close()

	priv, err := remoteclients.GeneratePrivateKey()
	sharedutils.CheckError(err)
	pub, err := remoteclients.GeneratePublicKey(priv)
	sharedutils.CheckError(err)
	auth.PrivateKey = base64.StdEncoding.EncodeToString(priv[:])
	auth.PublicKey = base64.StdEncoding.EncodeToString(pub[:])
	spew.Dump(auth)
	err = json.NewEncoder(f).Encode(&auth)
	sharedutils.CheckError(err)
	return priv, pub
}

func listenEvents(device *device.Device, profile profile.Profile) {
	chal, err := profile.GetServerChallenge(&profile)
	sharedutils.CheckError(err)
	priv, err := remoteclients.B64KeyToBytes(profile.PrivateKey)
	sharedutils.CheckError(err)
	pub, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	sharedutils.CheckError(err)
	serverPub, err := remoteclients.URLB64KeyToBytes(chal.PublicKey)
	sharedutils.CheckError(err)

	myID := base64.URLEncoding.EncodeToString(pub[:])
	c := api.GLPPrivateClient(priv, pub, serverPub)
	c.Start()
	for {
		select {
		case e := <-c.EventsChan:
			event := api.Event{}
			err := json.Unmarshal(e.Data, &event)
			sharedutils.CheckError(err)
			if event.Type == "new_peer" && event.Data["id"].(string) != myID {
				startPeer(device, profile, event.Data["id"].(string))
			}
		}
	}
}

func startPeer(device *device.Device, prof profile.Profile, peerID string) {
	peerProfile, err := prof.GetPeerProfile(peerID)
	if err != nil {
		logger.Error.Println("Unable to fetch profile for peer", peerID, ". Error:", err)
		logger.Error.Println(debug.Stack())
	} else {
		go func(peerID string, peerProfile profile.PeerProfile) {
			for {
				func() {
					defer func() {
						if r := recover(); r != nil {
							logger.Error.Println("Recovered error", r, "while handling peer", peerProfile.PublicKey, ". Will attempt to connect to it again.")
						}
					}()
					methodType := "stun"
					method, _ := hole.Create(ctx, methodType, device, logger, prof, peerProfile)
					method.Start()
				}()
			}
		}(peerID, peerProfile)
	}
}
