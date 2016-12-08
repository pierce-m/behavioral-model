#include "register.h"

namespace externs {

void Register::init() {
  v.resize(size.get<size_t>());
}

void Register::read(Data &_return, const Data &index) {
  _return = v.at(index.get<size_t>());
}
                                                           
void Register::write(const Data &index, const Data &value) {
  v.at(index.get<size_t>()) = value;
}

} // namespace externs

BM_REGISTER_EXTERN_W_NAME(register, externs::Register);
BM_REGISTER_EXTERN_W_NAME_METHOD(register, externs::Register, read, Data &, const Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(register, externs::Register, write, const Data &, const Data &);

int import_register() { return 0; }

