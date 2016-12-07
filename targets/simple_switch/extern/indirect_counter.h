#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/P4Objects.h>

using bm::ExternType;
using bm::Data;

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
