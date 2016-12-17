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

#include <gtest/gtest.h>

#include "extern/register.h"

using externs::Register;
using bm::ExternFactoryMap;

extern int import_register();

class ExternRegisterTest : public ::testing::Test {
 public:
  static void SetUpTestCase() {
    import_register();
  }
};

TEST_F(ExternRegisterTest, Register) {
  Data register_size(3);
  auto extern_instance =
      ExternFactoryMap::get_instance()->get_extern_instance("Register");
  extern_instance->_register_attributes();
  extern_instance->_set_attribute<Data>("size", register_size);
  extern_instance->init();
  auto register_instance =
      dynamic_cast<Register *>(extern_instance.get());

  Data write_val(7), write_index(2), read_val;
  register_instance->write(write_index, write_val);
  register_instance->read(&read_val, write_index);
  ASSERT_EQ(read_val.get_uint(), write_val.get_uint());
}
