AM_CPPFLAGS =  -I$(srcdir)/../../../thrift_src/gen-cpp
bin_PROGRAMS = corsa_test
corsa_test_SOURCES = corsa_test.cpp openflow_helper.c
corsa_test_LDADD = -lJudy -lnanomsg -lthrift $(srcdir)/../../../thrift_src/libruntimestubs.la
corsa_test_LDFLAGS = -pthread
