/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 *
 * This implements userspace semantics of "sticky sockets", modeled after
 * WireGuard's kernelspace implementation. This is more or less a straight port
 * of the sticky-sockets.c example code:
 * https://git.zx2c4.com/WireGuard/tree/contrib/examples/sticky-sockets/sticky-sockets.c
 *
 * Currently there is no way to achieve this within the net package:
 * See e.g. https://github.com/golang/go/issues/17930
 * So this code is remains platform dependent.
 */

package device

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/rwcancel"
)

// 路由监控
func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	// 如果不是linux socket bind
	if _, ok := bind.(*conn.LinuxSocketBind); !ok {
		return nil, nil
	}

	// create netlink socket
	netlinkSock, err := createNetlinkRouteSocket()
	if err != nil {
		return nil, err
	}
	netlinkCancel, err := rwcancel.NewRWCancel(netlinkSock)
	if err != nil {
		unix.Close(netlinkSock)
		return nil, err
	}

	// 用来listen 路由规则的修改
	go device.routineRouteListener(bind, netlinkSock, netlinkCancel)

	return netlinkCancel, nil
}

// 路由规则到修改
func (device *Device) routineRouteListener(bind conn.Bind, netlinkSock int, netlinkCancel *rwcancel.RWCancel) {
	type peerEndpointPtr struct {
		peer     *Peer
		endpoint *conn.Endpoint
	}
	var reqPeer map[uint32]peerEndpointPtr
	var reqPeerLock sync.Mutex

	defer netlinkCancel.Close()
	defer unix.Close(netlinkSock)

	for msg := make([]byte, 1<<16); ; {
		var err error
		var msgn int
		for {
			// 从netlink 获取消息
			msgn, _, _, _, err = unix.Recvmsg(netlinkSock, msg[:], nil, 0)
			// epoll 类似，如果是非eagain或者是interrupt
			// 那么直接跳出去
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			// 在读一次
			if !netlinkCancel.ReadyRead() {
				return
			}
		}
		if err != nil {
			return
		}

		// 消息是4字节对齐
		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                          Length                             |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |            Type              |           Flags              |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                      Sequence Number                        |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                      Process ID (PID)                       |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {

			// https://medium.com/@mdlayher/linux-netlink-and-go-part-1-netlink-4781aaeeaca8
			// netlink 头信息
			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			// 不是一个完整的包
			// hdr.Len表示整个的包
			if uint(hdr.Len) > uint(len(remain)) {
				break
			}

			switch hdr.Type {
			// 如果是删除路由规则或者是,添加路由规则
			case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
				if hdr.Seq <= MaxPeers && hdr.Seq > 0 {
					// 不是一个完整的包
					if uint(len(remain)) < uint(hdr.Len) {
						break
					}
					// 完整的大于一个routine的消息 + 头
					if hdr.Len > unix.SizeofNlMsghdr+unix.SizeofRtMsg {
						// netlink 属性
						attr := remain[unix.SizeofNlMsghdr+unix.SizeofRtMsg:]
						for {
							if uint(len(attr)) < uint(unix.SizeofRtAttr) {
								break
							}
							attrhdr := *(*unix.RtAttr)(unsafe.Pointer(&attr[0]))
							if attrhdr.Len < unix.SizeofRtAttr || uint(len(attr)) < uint(attrhdr.Len) {
								// 不是一个完整的属性
								break
							}
							// 如果是设置output interface index
							// https://man7.org/linux/man-pages/man7/rtnetlink.7.html
							if attrhdr.Type == unix.RTA_OIF && attrhdr.Len == unix.SizeofRtAttr+4 {
								// 设备索引号
								ifidx := *(*uint32)(unsafe.Pointer(&attr[unix.SizeofRtAttr]))
								reqPeerLock.Lock()
								// 如果是空，没有初始化
								if reqPeer == nil {
									reqPeerLock.Unlock()
									break
								}
								// 找到请求的节点
								pePtr, ok := reqPeer[hdr.Seq]
								reqPeerLock.Unlock()
								if !ok {
									break
								}
								pePtr.peer.Lock()
								if &pePtr.peer.endpoint != pePtr.endpoint {
									pePtr.peer.Unlock()
									break
								}

								// 是当前的设备号
								if uint32(pePtr.peer.endpoint.(*conn.LinuxSocketEndpoint).Src4().Ifindex) == ifidx {
									pePtr.peer.Unlock()
									break
								}
								// 清空原地址信息
								pePtr.peer.endpoint.(*conn.LinuxSocketEndpoint).ClearSrc()
								pePtr.peer.Unlock()
							}
							// 获取下一个属性
							attr = attr[attrhdr.Len:]
						} // 结束遍历所有的属性
					}
					// 不是一个完整的消息
					break
				}  // end of if
				reqPeerLock.Lock()
				reqPeer = make(map[uint32]peerEndpointPtr)
				reqPeerLock.Unlock()
				// 执行一个goroutine
				go func() {
					device.peers.RLock()
					i := uint32(1)
					// 对设备下的每个endpoint
					for _, peer := range device.peers.keyMap {
						peer.RLock()
						if peer.endpoint == nil {
							peer.RUnlock()
							continue
						}
						// 对端的节点地址信息
						nativeEP, _ := peer.endpoint.(*conn.LinuxSocketEndpoint)
						if nativeEP == nil {
							peer.RUnlock()
							continue
						}

						// 如果不是本设备
						if nativeEP.IsV6() || nativeEP.Src4().Ifindex == 0 {
							peer.RUnlock()
							break
						}
						// http://iijean.blogspot.com/2010/03/howto-get-list-of-network-interfaces-in.html
						// netlink message
						nlmsg := struct {
							// msg header
							hdr     unix.NlMsghdr
							// 路由消息本身
							msg     unix.RtMsg
							// 消息属性
							dsthdr  unix.RtAttr
							// 目的地址
							dst     [4]byte
							// 源地址信息
							srchdr  unix.RtAttr
							src     [4]byte
							markhdr unix.RtAttr
							mark    uint32
						}{
							// 请求获取路由
							unix.NlMsghdr{
								Type:  uint16(unix.RTM_GETROUTE),
								Flags: unix.NLM_F_REQUEST,
								Seq:   i,
							},
							// 路由消息
							unix.RtMsg{
								Family:  unix.AF_INET,
								Dst_len: 32,
								Src_len: 32,
							},
							//  目标属性
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_DST, // 路由的目标地址
							},

							// 目的地址
							nativeEP.Dst4().Addr,
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_SRC, // 路由的源地址
							},
							nativeEP.Src4().Src,
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_MARK,
							},
							device.net.fwmark,
						}
						// 设置整个消息的长度
						nlmsg.hdr.Len = uint32(unsafe.Sizeof(nlmsg))
						reqPeerLock.Lock()
						// 发起请求
						reqPeer[i] = peerEndpointPtr{
							peer:     peer,
							endpoint: &peer.endpoint,
						}
						reqPeerLock.Unlock()
						peer.RUnlock()
						i++
						// 通过netlink发送消息给内核，获取相关节点的路由信息
						_, err := netlinkCancel.Write((*[unsafe.Sizeof(nlmsg)]byte)(unsafe.Pointer(&nlmsg))[:])
						if err != nil {
							break
						}
					}
					device.peers.RUnlock()
				}()
			} // end of case // 是路由的消息

			// 处理来一个完整的包
			remain = remain[hdr.Len:]
		} // end of for
	}
}

// see https://medium.com/@mdlayher/linux-netlink-and-go-part-1-netlink-4781aaeeaca8
func createNetlinkRouteSocket() (int, error) {
	// AF_NETLINK
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		// ipv4的路由
		Groups: unix.RTMGRP_IPV4_ROUTE,
	}
	err = unix.Bind(sock, saddr)
	if err != nil {
		unix.Close(sock)
		return -1, err
	}
	return sock, nil
}
