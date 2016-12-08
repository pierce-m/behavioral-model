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

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/P4Objects.h>

using bm::ExternType;
using bm::Data;

namespace externs {

class IndirectCounter : public ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(size);
    BM_EXTERN_ATTRIBUTE_ADD(type); // Not used currently as we count both
  }

  void init() override;

  void count(const Data &index);

  // for testing purposes only -- leave unregistered
  void read(Data &_pkts_return, Data &_bytes_return, const Data &index);

 private:
  // constructor params
  Data size;
  std::string type;

  // implementing structure
  std::vector<Data> packets;
  std::vector<Data> bytes;
};

} // namespace externs
