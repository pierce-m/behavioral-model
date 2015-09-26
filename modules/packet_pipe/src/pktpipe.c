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

#include <nanomsg/nn.h>
#include <nanomsg/pair.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "pktpipe/pktpipe.h"

struct pktpipe_mgr_s {
  int sock;
  int receiver_set;
  pktpipe_receiver_t packet_receiver;
  void *cookie;
  pthread_t recv_thread;
  pthread_mutex_t lock;
  int stop_thread;
};

typedef struct {
  int port;
  int len;
} __attribute__((packed)) packet_hdr_t;

static void *run_receive(void *arg) {
  pktpipe_mgr_t *mgr = (pktpipe_mgr_t *) arg;

  struct nn_msghdr msghdr;
  struct nn_iovec iov[2];
  packet_hdr_t packet_hdr;
  char data[4096]; // frames cannot exceed this
  iov[0].iov_base = &packet_hdr;
  iov[0].iov_len = sizeof(packet_hdr);
  iov[1].iov_base = data;
  iov[1].iov_len = sizeof(data); // apparently only max size needed ?
  memset(&msghdr, 0, sizeof(msghdr));
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;

  while(1) {

    if(nn_recvmsg(mgr->sock, &msghdr, 0) <= 0) continue;
    
    pthread_mutex_lock(&mgr->lock);

    printf("packet received on port %d\n", packet_hdr.port);
    if(mgr->receiver_set) {
      printf("calling receiver\n");
      mgr->packet_receiver(packet_hdr.port, data, packet_hdr.len, mgr->cookie);
    }
    else {
      printf("no receiver, dropping packet\n");
    }

    if(mgr->stop_thread) {
      pthread_mutex_unlock(&mgr->lock);
      break;
    }

    pthread_mutex_unlock(&mgr->lock);
  }

  return NULL;
}

void pktpipe_init(pktpipe_mgr_t **mgr, const char *addr) {
  pktpipe_mgr_t *mgr_;
  mgr_ = (pktpipe_mgr_t *) malloc(sizeof(*mgr_));
  memset(mgr_, 0, sizeof(*mgr_));
  mgr_->sock = nn_socket(AF_SP, NN_PAIR);
  assert(mgr_->sock >= 0);
  int to = 200;
  assert(nn_setsockopt(mgr_->sock, NN_SOL_SOCKET, NN_RCVTIMEO, &to, sizeof(to)) >= 0);
  assert(nn_connect(mgr_->sock, addr) >= 0);
  pthread_mutex_init(&mgr_->lock, NULL);
  pthread_create(&mgr_->recv_thread, NULL, run_receive, mgr_);
  *mgr = mgr_;
}

void pktpipe_set_packet_receiver(pktpipe_mgr_t *mgr,
				 pktpipe_receiver_t packet_receiver,
				 void *cookie) {
  pthread_mutex_lock(&mgr->lock);
  mgr->packet_receiver = packet_receiver;
  mgr->cookie = cookie;
  mgr->receiver_set = 1;
  pthread_mutex_unlock(&mgr->lock);
}

void pktpipe_send(pktpipe_mgr_t *mgr,
		  int port_num, char *buffer, int len) {
  struct nn_msghdr msghdr;
  memset(&msghdr, 0, sizeof(msghdr));
  struct nn_iovec iov[2];
  packet_hdr_t packet_hdr;
  iov[0].iov_base = &packet_hdr;
  iov[0].iov_len = sizeof(packet_hdr);
  packet_hdr.port = port_num;
  packet_hdr.len = len;
  iov[1].iov_base = buffer;
  iov[1].iov_len = len;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;
  nn_sendmsg(mgr->sock, &msghdr, 0);
  printf("message sent\n");
}

void pktpipe_destroy(pktpipe_mgr_t *mgr) {
  pthread_mutex_lock(&mgr->lock);
  mgr->stop_thread = 1;
  pthread_mutex_unlock(&mgr->lock);

  pthread_join(mgr->recv_thread, NULL);

  pthread_mutex_destroy(&mgr->lock);
  nn_shutdown(mgr->sock, 0);

  free(mgr);
}
