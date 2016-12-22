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

#ifndef EXTERNS_CHECKSUM16_H_
#define EXTERNS_CHECKSUM16_H_

#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/data.h>

using bm::ExternType;
using bm::Data;

namespace externs {

class Checksum16 : public ExternType {
 private:
  const std::string algorithm{"crc16"};
 public:
  BM_EXTERN_ATTRIBUTES {
  }
  void init() override;
  void get(Data &checksum_val, const Data &field_list_id);
};

} // namespace externs

#endif // EXTERNS_CHECKSUM16_H_
