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
