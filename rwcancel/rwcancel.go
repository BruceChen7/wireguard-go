// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

// Package rwcancel implements cancelable read/write operations on
// a file descriptor.
package rwcancel

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type RWCancel struct {
	// 这个fd 是netlinksock
	fd int
	// 是os pipe
	// 用来关闭读端
	closingReader *os.File
	closingWriter *os.File
}

func NewRWCancel(fd int) (*RWCancel, error) {
	// 将被wrap的fd设置为non-block
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	// netlink
	rwcancel := RWCancel{fd: fd}

	// 创建pipe
	rwcancel.closingReader, rwcancel.closingWriter, err = os.Pipe()
	if err != nil {
		return nil, err
	}

	return &rwcancel, nil
}

func RetryAfterError(err error) bool {
	// 如果是eagin或者interrupt
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}

func (rw *RWCancel) ReadyRead() bool {
	closeFd := int32(rw.closingReader.Fd())

	// 监听读事件, 2个fd, 一个用来
	pollFds := []unix.PollFd{{Fd: int32(rw.fd), Events: unix.POLLIN}, {Fd: closeFd, Events: unix.POLLIN}}
	var err error
	for {
		_, err = unix.Poll(pollFds, -1)
		if err == nil || !RetryAfterError(err) {
			break
		}
	}
	if err != nil {
		return false
	}
	if pollFds[1].Revents != 0 {
		return false
	}
	return pollFds[0].Revents != 0
}

func (rw *RWCancel) ReadyWrite() bool {
	// 注意这里的fd是pipe 的read fd
	closeFd := int32(rw.closingReader.Fd())
	pollFds := []unix.PollFd{{Fd: int32(rw.fd), Events: unix.POLLOUT}, {Fd: closeFd, Events: unix.POLLOUT}}
	var err error
	for {
		_, err = unix.Poll(pollFds, -1)
		if err == nil || !RetryAfterError(err) {
			break
		}
	}
	if err != nil {
		return false
	}

	// 已经关闭
	if pollFds[1].Revents != 0 {
		return false
	}
	return pollFds[0].Revents != 0
}

func (rw *RWCancel) Read(p []byte) (n int, err error) {
	for {
		n, err := unix.Read(rw.fd, p)
		if err == nil || !RetryAfterError(err) {
			return n, err
		}
		// 直接返回连接关闭
		if !rw.ReadyRead() {
			return 0, os.ErrClosed
		}
	}
}

func (rw *RWCancel) Write(p []byte) (n int, err error) {
	for {
		// 给对应的netlink fd写相关数据，和内核进程通信
		n, err := unix.Write(rw.fd, p)
		if err == nil || !RetryAfterError(err) {
			return n, err
		}
		// netlink关闭了
		if !rw.ReadyWrite() {
			return 0, os.ErrClosed
		}
	}
}

func (rw *RWCancel) Cancel() (err error) {
	// 通过pipe来通知
	_, err = rw.closingWriter.Write([]byte{0})
	return
}

// 关闭读端和写端
func (rw *RWCancel) Close() {
	rw.closingReader.Close()
	rw.closingWriter.Close()
}
