#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/P4Objects.h>

using bm::ExternType;
using bm::Data;

class IndirectCounter : public ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(size);
    BM_EXTERN_ATTRIBUTE_ADD(type);
  }

  void init() override {
    v.resize(size.get<size_t>());
  }

  void count(const Data &index) {
    v.at(index.get<size_t>()).increment();
  }

 private:
  // constructor params
  Data size;
  Data type;

  // implementing structure
  std::vector<Data> v;
};

BM_REGISTER_EXTERN_W_NAME(counter, IndirectCounter);
BM_REGISTER_EXTERN_W_NAME_METHOD(counter, IndirectCounter, count, const Data &);

int import_indirect_counter() { return 0; }
