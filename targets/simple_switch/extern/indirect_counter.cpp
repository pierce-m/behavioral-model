
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

#include "indirect_counter.h"

using bm::Packet;

namespace externs {

void IndirectCounter::init() {
  packets.resize(size.get<size_t>());
  bytes.resize(size.get<size_t>());
}

void IndirectCounter::count(const Data &index) {
  Data *d;
  d = &packets.at(index.get<size_t>());
  d->add(Data(1), *d);

  d = &bytes.at(index.get<size_t>());
  d->add(Data(get_packet().get_ingress_length()), *d);
}

// for testing purposes only -- leave unregistered
void IndirectCounter::read(Data &_pkts_return,
                           Data &_bytes_return,
                           const Data &index) {
  _pkts_return = packets.at(index.get<size_t>());
  _bytes_return = bytes.at(index.get<size_t>());
}

} // namespace externs

BM_REGISTER_EXTERN_W_NAME(counter, externs::IndirectCounter);
BM_REGISTER_EXTERN_W_NAME_METHOD(counter, externs::IndirectCounter, count, const Data &);

int import_indirect_counter() { return 0; }
