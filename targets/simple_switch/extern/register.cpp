#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/P4Objects.h>

using bm::ExternType;
using bm::Data;

// any T that can be represented by Data
class Register : public ExternType {
 public:
  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(size);
  }
                  
  void init() override {
    v.resize(size.get<size_t>());
  }

  // needs to return void
  // x = reg.read(99)
  // -> Register::read(x, 99)
  // x = reg.read(99) + reg.read(77);
  // x1 <- reg.read(99);
  // x2 <- reg.read(77);
  // x <- x1 + x2;
  void read(Data &_return, const Data &index) {
    _return = v.at(index.get<size_t>());
  }
                                                             
  void write(const Data &index, const Data &value) {
    v.at(index.get<size_t>()) = value;
  }
                                                                            
 private:
  // constructor
  Data size;

  // implementing structure
  std::vector<Data> v;
};

BM_REGISTER_EXTERN_W_NAME(register, Register);
BM_REGISTER_EXTERN_W_NAME_METHOD(register, Register, read, Data &, const Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(register, Register, write, const Data &, const Data &);

int import_register() { return 0; }
