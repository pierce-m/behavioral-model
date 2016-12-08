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

#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/actions.h>
#include <bm/bm_sim/phv.h>

#include "extern/indirect_counter.h"

using namespace bm;

extern int import_indirect_counter();

class ExternCounterTest : public ::testing::Test {
 public:
  static void SetUpTestCase() {
    import_indirect_counter();
  }

 protected:
  PHVFactory phv_factory;
  PHV *phv{nullptr};
  HeaderType testHeaderType;
  header_id_t testHeader{0};

  std::unique_ptr<PHVSourceIface> phv_source{nullptr};
  std::unique_ptr<Packet> pkt{nullptr};

  ExternCounterTest()
      : testHeaderType("test_t", 0),
        phv_source(PHVSourceIface::make_phv_source()) {}

  virtual void SetUp() {
    int ingress_length = 14;
    phv_source->set_phv_factory(0, &phv_factory);
    pkt = std::unique_ptr<Packet>(new Packet(
        Packet::make_new(ingress_length, PacketBuffer(ingress_length),
                         phv_source.get())));
    phv = pkt->get_phv();
  }

  static ActionPrimitive_ *get_extern_primitive(
      const std::string &extern_name, const std::string &method_name) {
    return ActionOpcodesMap::get_instance()->get_primitive(
        "_" + extern_name + "_" + method_name);
  }

  void execute_count(ExternType *instance, size_t index) {
    ActionFn testActionFn("test_action", 0);
    ActionFnEntry testActionFnEntry(&testActionFn);
    auto primitive = get_extern_primitive("counter", "count");
    testActionFn.push_back_primitive(primitive);
    testActionFn.parameter_push_back_extern_instance(instance);
    testActionFn.parameter_push_back_const(Data(index));
    testActionFnEntry(pkt.get());
  }

  void execute(ExternType *instance, size_t index) {
    execute_count(instance, index);
  }
};

TEST_F(ExternCounterTest, IndirectCounter) {
  Data counter_size(3);
  std::string counter_type("packets_and_bytes");

  auto extern_instance =
      ExternFactoryMap::get_instance()->get_extern_instance("counter");
  extern_instance->_register_attributes();
  extern_instance->_set_attribute<Data>("size", counter_size);
  extern_instance->_set_attribute<std::string>("type", counter_type);
  extern_instance->init();
  auto counter_instance =
      dynamic_cast<externs::IndirectCounter *>(extern_instance.get());
  execute(counter_instance, 2);

  Data packet_result, bytes_result, index(2);
  counter_instance->read(packet_result, bytes_result, index);
  ASSERT_EQ((unsigned) 1, packet_result.get_uint());
  ASSERT_EQ((unsigned) 14, bytes_result.get_uint());
}
