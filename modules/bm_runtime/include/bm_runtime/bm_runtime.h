#ifndef _BM_RUNTIME_BM_RUNTIME_H_
#define _BM_RUNTIME_BM_RUNTIME_H_

#ifndef USING_FACEBOOK_THRIFT
  #include <thrift/processor/TMultiplexedProcessor.h>

  using namespace ::apache::thrift;
  using namespace ::apache::thrift::protocol;
  using namespace ::apache::thrift::transport;
#else
#endif

#include <bm_sim/switch.h>


namespace bm_runtime {

#ifndef USING_FACEBOOK_THRIFT
  using boost::shared_ptr;
#endif

extern Switch *switch_;

#ifndef USING_FACEBOOK_THRIFT
  extern TMultiplexedProcessor *processor_;
#endif

template <typename Handler, typename Processor>
int add_service(const std::string &service_name) {
#ifndef USING_FACEBOOK_THRIFT
  shared_ptr<Handler> handler(new Handler(switch_));
  processor_->registerProcessor(service_name,
				shared_ptr<TProcessor>(new Processor(handler)));
#endif
}

int start_server(Switch *sw, int port);

}

#endif
