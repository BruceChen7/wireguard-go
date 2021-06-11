// +build linux darwin freebsd openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	IpcErrorIO        = -int64(unix.EIO)
	IpcErrorProtocol  = -int64(unix.EPROTO)
	IpcErrorInvalid   = -int64(unix.EINVAL)
	IpcErrorPortInUse = -int64(unix.EADDRINUSE)
	IpcErrorUnknown   = -55 // ENOANO
)

// socketDirectory is variable because it is modified by a linker
// flag in wireguard-android.
var socketDirectory = "/var/run/wireguard"

func sockPath(iface string) string {
	return fmt.Sprintf("%s/%s.sock", socketDirectory, iface)
}

func UAPIOpen(name string) (*os.File, error) {
	// 创建unix socket文件
	if err := os.MkdirAll(socketDirectory, 0755); err != nil {
		return nil, err
	}

	socketPath := sockPath(name)
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}

	oldUmask := unix.Umask(0077)
	// 恢复之前的master
	defer unix.Umask(oldUmask)

	// 创建unix桃姐子
	listener, err := net.ListenUnix("unix", addr)
	if err == nil {
		return listener.File()
	}

	// Test socket, if not in use cleanup and try again.
	if _, err := net.Dial("unix", socketPath); err == nil {
		return nil, errors.New("unix socket in use")
	}
	if err := os.Remove(socketPath); err != nil {
		return nil, err
	}
	listener, err = net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	return listener.File()
}
