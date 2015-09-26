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

#ifndef _BM_PACKET_IN_NANOMSG_H_
#define _BM_PACKET_IN_NANOMSG_H_

#include <string>
#include <thread>
#include <atomic>

#include "nn.h"

class PacketInNanomsg
{
public:
  typedef std::function<void(int port_num, const char *buffer, int len, void *cookie)> PacketHandler;

public:
  PacketInNanomsg(const std::string &addr,
		  const PacketHandler &handler, void *cookie);

  void start();

  void stop();

  void transmit_(int port, const char *buffer, int len);

  ~PacketInNanomsg();

public:
  static void transmit(int port_num, const char *buffer, int len,
		       void *cookie) {
    ((PacketInNanomsg *) cookie)->transmit_(port_num, buffer, len);
  }

private:
  void receive_loop();

private:
  std::string addr;
  nn::socket s;
  std::thread receive_thread{};
  std::atomic<bool> stop_receive_thread{false};
  std::atomic<bool> started{false};
  PacketHandler handler;
  void *cookie{nullptr};
};

#endif
