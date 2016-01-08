#ifndef _BM_RUNTIME_BM_RUNTIME_H_
#define _BM_RUNTIME_BM_RUNTIME_H_

#include <thrift/processor/TMultiplexedProcessor.h>

#include <bm_sim/switch.h>

namespace bm_runtime {

using namespace ::p4::thrift;
using namespace ::p4::thrift::protocol;
using namespace ::p4::thrift::transport;
using boost::shared_ptr;

extern TMultiplexedProcessor *processor_;
extern SwitchWContexts *switch_;

template <typename Handler, typename Processor, typename S>
int add_service(const std::string &service_name) {
  // TODO(antonin): static_cast too error prone here?
  shared_ptr<Handler> handler(new Handler(static_cast<S *>(switch_)));
  processor_->registerProcessor(service_name,
				shared_ptr<TProcessor>(new Processor(handler)));
}

int start_server(SwitchWContexts *sw, int port);

}

#endif
