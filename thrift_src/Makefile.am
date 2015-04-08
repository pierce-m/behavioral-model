BUILT_SOURCES = gen-cpp/runtime_constants.cpp  gen-cpp/runtime_constants.h  gen-cpp/Runtime.cpp  gen-cpp/Runtime.h  gen-cpp/Runtime_server.skeleton.cpp  gen-cpp/runtime_types.cpp  gen-cpp/runtime_types.h

noinst_LIBRARIES = libthrift.a
libthrift_a_SOURCES = \
	${BUILT_SOURCES}

${BUILT_SOURCES} : runtime.thrift
	$(THRIFT) --gen cpp -r $<

clean-local:
	rm -rf gen-cpp gen-py
