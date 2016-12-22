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

#include "checksum.h"

#include <bm/bm_sim/P4Objects.h>

namespace externs {

using bm::P4Objects;
using bm::FieldList;
using bm::BufBuilder;
using bm::Calculation;

void Checksum16::init() {}

void Checksum16::get(Data &checksum_val, const Data &field_list_id) {
  P4Objects &p4_objects = get_p4objects();
  FieldList *fl = p4_objects.get_field_list(field_list_id.get_uint64());

  BufBuilder builder;
  for (auto field = fl->begin(); field != fl->end(); field++) {
    builder.push_back_field(field->header, field->offset);
  }

  Calculation calc(builder, algorithm);
  checksum_val.set(calc.output(get_packet()));
}

BM_REGISTER_EXTERN(Checksum16);
BM_REGISTER_EXTERN_METHOD(Checksum16, get, Data &, const Data &);

} // namespace externs

int import_checksum16() { return 0; }
