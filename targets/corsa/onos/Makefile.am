INDIGO_DIR = ../../../modules/bfofagent/submodules/indigo
INDIGO_INC_DIR = -I$(INDIGO_DIR)
INCS = $(INDIGO_INC_DIR)/modules/OFConnectionManager/module/inc $(INDIGO_INC_DIR)/submodules/infra/modules/AIM/module/inc $(INDIGO_INC_DIR)/modules/indigo/module/inc $(INDIGO_INC_DIR)/submodules/loxigen-artifacts/loci/inc  $(INDIGO_INC_DIR)/modules/SocketManager/module/inc $(INDIGO_INC_DIR)/modules/OFStateManager/module/inc 
LIB_DIR = $(INDIGO_DIR)/targets/utests/OFConnectionManager/build/gcc-local/lib
LIBS = $(LIB_DIR)/OFStateManager.a $(LIB_DIR)/OFConnectionManager.a $(LIB_DIR)/AIM.a $(LIB_DIR)/SocketManager.a $(LIB_DIR)/indigo.a $(LIB_DIR)/loci.a $(LIB_DIR)/cjson.a $(LIB_DIR)/Configuration.a $(LIB_DIR)/debug_counter.a $(LIB_DIR)/timer_wheel.a $(LIB_DIR)/BigRing.a $(LIB_DIR)/OS.a $(LIB_DIR)/BigHash.a $(LIB_DIR)/minimatch.a $(LIB_DIR)/BigList.a 

AM_CPPFLAGS =  -I$(srcdir)/../../../pd_gen/fixed-cpp/src  -I$(srcdir)/../../../pd_gen/fixed-cpp/include  -I$(srcdir)/../../../pd_gen/gen-cpp/include -fpermissive -Wsign-compare $(INCS)
AM_CFLAGS = -Wsign-compare  $(INCS)

bin_PROGRAMS = onos
onos_SOURCES = onos.cpp openflow_helper.c
onos_LDADD = -lJudy -lnanomsg -lthrift $(srcdir)/../../../thrift_src/libruntimestubs.la  $(LIBS)
onos_LDFLAGS = -pthread

