#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/P4Objects.h>

using bm::ExternType;
using bm::Data;

namespace externs {

class Checksum16 : public ExternType {
 public:
  void init() override;

  void get(Data *checksum_val, const Data &d);
};

} // namespace externs
