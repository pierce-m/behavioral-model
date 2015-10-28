SUBDIRS = . learn_client

AM_CPPFLAGS = -I$(srcdir)/../../modules/bm_sim/include \
-I$(srcdir)/../../modules/bf_lpm_trie/include \
-I$(srcdir)/../../third_party/jsoncpp/include \
-I$(srcdir)/../../modules/bm_runtime/include \
-I$(srcdir)/../../modules/BMI/include 
bin_PROGRAMS = l2_switch
l2_switch_SOURCES = l2_switch.cpp l2_switch.h primitives.h simplelog.h
l2_switch_LDFLAGS = -l:$(srcdir)/../../modules/bm_runtime/.libs/libbmruntime.a \
-l:$(srcdir)/../../modules/bm_sim/.libs/libbmsim.a \
-l:$(srcdir)/../../modules/bf_lpm_trie/.libs/libbflpmtrie.a \
-l:$(srcdir)/../../thrift_src/.libs/libruntimestubs.a \
-l:$(srcdir)/../../thrift_src/.libs/libruntimestubs.a \
-l:$(srcdir)/../../modules/BMI/.libs/libbmi.a \
-l:$(srcdir)/../../third_party/jsoncpp/.libs/libjson.a \
-lboost_system -lboost_thread -lthrift \
-lboost_program_options -pthread

if FACEBOOK_THRIFT
  AM_CPPFLAGS += \
    -DUSING_FACEBOOK_THRIFT

  l2_switch_LDFLAGS += \
    -l:$(HOME)/git/p4factory/submodules/fboss/external/fbthrift/thrift/lib/cpp2/.libs/libthriftcpp2.a \
    -l:$(HOME)/git/p4factory/submodules/fboss/external/fbthrift/thrift/lib/cpp2/libsaslstubs.a -lfolly \
    -lwangle -lssl -lgflags -lglog -lnuma -lgssapi_krb5     
endif
