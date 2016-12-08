#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/P4Objects.h>

using bm::ExternType;
using bm::Data;

namespace externs {

class Register : public ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(size);
  }
                  
  void init() override;

  void read(Data &_return, const Data &index);

  void write(const Data &index, const Data &value);

 private:
  // constructor
  Data size;

  // implementing structure
  std::vector<Data> v;
};

} // namespace externs
