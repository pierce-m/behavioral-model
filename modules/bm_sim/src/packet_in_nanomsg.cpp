/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <nanomsg/pair.h>
#include <iostream> // temp

#include "bm_sim/packet_in_nanomsg.h"

PacketInNanomsg::PacketInNanomsg(const std::string &addr,
				 const PacketHandler &handler, void *cookie)
  : addr(addr), s(AF_SP, NN_PAIR), handler(handler), cookie(cookie) {
  std::cout << "socket: " << addr << std::endl;
  s.bind(addr.c_str());
  int rcv_timeout_ms = 200;
  s.setsockopt(NN_SOL_SOCKET, NN_RCVTIMEO, &rcv_timeout_ms, sizeof(rcv_timeout_ms));
}

void
PacketInNanomsg::start() {
  if(started || stop_receive_thread)
    return;
  receive_thread = std::thread(&PacketInNanomsg::receive_loop, this);
  started = true;
}

void
PacketInNanomsg::stop() {
  if(started) {
    stop_receive_thread = true;
    receive_thread.join();
  }
}

PacketInNanomsg::~PacketInNanomsg() {
  stop();
}

typedef struct {
  int port;
  int len;
} __attribute__((packed)) packet_hdr_t;

void
PacketInNanomsg::transmit_(int port, const char *buffer, int len) {
  struct nn_msghdr msghdr;
  std::memset(&msghdr, 0, sizeof(msghdr));
  struct nn_iovec iov[2];
  packet_hdr_t packet_hdr;
  iov[0].iov_base = &packet_hdr;
  iov[0].iov_len = sizeof(packet_hdr);
  packet_hdr.port = port;
  packet_hdr.len = len;
  // TODO: remove copy
  std::unique_ptr<char []> data(new char[len]);
  std::copy(buffer, &buffer[len], data.get());
  iov[1].iov_base = data.get();
  iov[1].iov_len = len;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;
  s.sendmsg(&msghdr, 0);
  std::cout << "packet send for port " << port << std::endl;
}

void
PacketInNanomsg::receive_loop() {
  struct nn_msghdr msghdr;
  struct nn_iovec iov[2];
  packet_hdr_t packet_hdr;
  char data[4096]; // frames cannot exceed this
  iov[0].iov_base = &packet_hdr;
  iov[0].iov_len = sizeof(packet_hdr);
  iov[1].iov_base = data;
  iov[1].iov_len = sizeof(data); // apparently only max size needed ?
  std::memset(&msghdr, 0, sizeof(msghdr));
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;

  while(!stop_receive_thread) {
    int rc = s.recvmsg(&msghdr, 0);
    if(rc < 0) continue;
    if(handler) {
      std::cout << "packet in received on port " << packet_hdr.port
		<< std::endl;
      handler(packet_hdr.port, data, packet_hdr.len, cookie);
    }
  }
}
