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

#ifndef _PACKET_PIPE_PKTPIPE_H_
#define _PACKET_PIPE_PKTPIPE_H_

typedef struct pktpipe_mgr_s pktpipe_mgr_t;

/* the library owns the memory, make a copy if you need before returning */
typedef void (*pktpipe_receiver_t)(int port_num, const char *buffer, int len,
				   void *cookie);

void pktpipe_init(pktpipe_mgr_t **mgr, const char *addr);

void pktpipe_set_packet_receiver(pktpipe_mgr_t *mgr,
				 pktpipe_receiver_t packet_receiver,
				 void *cookie);

/* you surrender the memory */
void pktpipe_send(pktpipe_mgr_t *mgr,
		  int port_num, char *buffer, int len);

void pktpipe_destroy(pktpipe_mgr_t *mgr);

#endif
