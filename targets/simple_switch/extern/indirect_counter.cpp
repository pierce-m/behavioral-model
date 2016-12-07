#include "indirect_counter.h"

using bm::Packet;

void IndirectCounter::init() {
  packets.resize(size.get<size_t>());
  bytes.resize(size.get<size_t>());
}

void IndirectCounter::count(const Data &index) {
  Data *d;
  d = &packets.at(index.get<size_t>());
  d->add(Data(1), *d);

  d = &bytes.at(index.get<size_t>());
  d->add(Data(get_packet().get_ingress_length()), *d);
}

// for testing purposes only -- leave unregistered
void IndirectCounter::read(Data &_pkts_return, Data &_bytes_return,
                           const Data &index) {
  _pkts_return = packets.at(index.get<size_t>());
  _bytes_return = bytes.at(index.get<size_t>());
}

BM_REGISTER_EXTERN_W_NAME(counter, IndirectCounter);
BM_REGISTER_EXTERN_W_NAME_METHOD(counter, IndirectCounter, count, const Data &);

int import_indirect_counter() { return 0; }
