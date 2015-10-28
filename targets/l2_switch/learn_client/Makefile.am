AM_CPPFLAGS =  -I$(srcdir)/../../../thrift_src/gen-cpp 
bin_PROGRAMS = learn_client
learn_client_SOURCES = learn_client.cpp nn.h
learn_client_LDADD = -lJudy -lnanomsg -lthrift $(srcdir)/../../../thrift_src/libruntimestubs.la
learn_client_LDFLAGS = -pthread

if FACEBOOK_THRIFT
  AM_CPPFLAGS += \
    -DUSING_FACEBOOK_THRIFT

  learn_client_LDFLAGS += \
    -l:$(HOME)/git/p4factory/submodules/fboss/external/fbthrift/thrift/lib/cpp2/.libs/libthriftcpp2.a \
    -l:$(HOME)/git/p4factory/submodules/fboss/external/fbthrift/thrift/lib/cpp2/libsaslstubs.a \
    -lfolly -lwangle -lssl -lgflags -lglog -lnuma -lgssapi_krb5
endif
