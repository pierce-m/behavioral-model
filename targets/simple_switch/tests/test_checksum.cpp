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
#include "extern/checksum.h"

#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/P4Objects.h>

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>

#include <fstream>

namespace fs = boost::filesystem;

using namespace bm;

extern int import_checksum16();

class ExternChecksumTest: public ::testing::Test {
 public:
  static void SetUpTestCase() {
    import_checksum16();
  }

 protected:
  PHVFactory phv_factory;
  PHV *phv{nullptr};
  std::unique_ptr<PHVSourceIface> phv_source{nullptr};
  std::unique_ptr<Packet> pkt{nullptr};

  HeaderType testHeaderType;
  header_id_t testHeader{0};

  LookupStructureFactory lookup_factory;
  P4Objects p4objects;
  
  static const std::string testdata_dir;
  static const std::string test_json;

  ExternChecksumTest()
     : phv_source(PHVSourceIface::make_phv_source()),
       testHeaderType("h1_t", 0) {
    // TODO: header is replicated from json...maybe there's a better way?
    testHeaderType.push_back_field("f1", 64);
    testHeaderType.push_back_field("f2", 16);
    testHeaderType.push_back_field("ret", 16);
    phv_factory.push_back_header("h1", testHeader, testHeaderType);

    // TODO: not sure if this should go here
    fs::path json_path = fs::path(testdata_dir) / fs::path(test_json);
    std::ifstream ifs(json_path.string());
    p4objects.init_objects(&ifs, &lookup_factory);
  }

  virtual void SetUp() {
    int ingress_length = 12;
    phv_source->set_phv_factory(0, &phv_factory);
    pkt = std::unique_ptr<Packet>(new Packet(
        Packet::make_new(ingress_length, PacketBuffer(ingress_length),
                         phv_source.get())));
    phv = pkt->get_phv();
  }

  // tearDown?

  static ActionPrimitive_ *get_extern_primitive(
      const std::string &extern_name, const std::string &method_name) {
    return ActionOpcodesMap::get_instance()->get_primitive(
        "_" + extern_name + "_" + method_name);
  }

  void execute_to_field(ExternType *instance, p4object_id_t field_list_id) {
    ActionFn testActionFn("test_action", 0);
    ActionFnEntry testActionFnEntry(&testActionFn);
    auto primitive = get_extern_primitive("Checksum16", "get");
    testActionFn.push_back_primitive(primitive);
    testActionFn.parameter_push_back_extern_instance(instance);
    testActionFn.parameter_push_back_field(testHeader, 2);
    testActionFn.parameter_push_back_const(Data(field_list_id));
    testActionFnEntry(pkt.get());
  }
};

const std::string ExternChecksumTest::testdata_dir = TESTDATADIR;
const std::string ExternChecksumTest::test_json = "test_checksum.json";

TEST_F(ExternChecksumTest, Checksum16) {
  p4object_id_t fl_id = 1;

  auto extern_instance =
      ExternFactoryMap::get_instance()->get_extern_instance("Checksum16");
  extern_instance->_register_attributes();
  extern_instance->_set_p4objects(&p4objects);
  extern_instance->init();
  auto checksum_instance =
      dynamic_cast<externs::Checksum16 *>(extern_instance.get());
  
  pkt->get_phv()->get_header(testHeader).mark_valid();
  auto &input_f1 = pkt->get_phv()->get_field("h1.f1");
  input_f1.set("0x1234567890aa");
  auto &input_f2 = pkt->get_phv()->get_field("h1.f2");
  input_f2.set("0xbbcc");

  execute_to_field(checksum_instance, fl_id);

  auto input_ret = pkt->get_phv()->get_field("h1.ret");
  ASSERT_EQ(input_ret.get_uint(), 0xaf26);
}
