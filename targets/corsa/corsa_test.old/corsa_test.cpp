#include <iostream>

#include <thrift_endpoint.h>

#include <pd/pd_tables.h>
#include <pd/pd_static.h>
#include <pd/pd.h>

#define DEVICE_THRIFT_PORT 9090

extern "C" {
int openflow_setup(int argc, char* argv[]);
}

int main(int argc, char **argv) {
//  start_server();

  p4_pd_init();
  
  p4_pd_sess_hdl_t sess_hdl;
  p4_pd_client_init(&sess_hdl, 16);
  
  std::cerr << "session handle is " << sess_hdl << std::endl;
  
  p4_pd_dev_target_t dev_tgt = {0, 0xFF};
  p4_pd_entry_hdl_t entry_hdl;

  /* P4 dependent initialization */
  p4_pd_corsa_init(sess_hdl, NULL);
  p4_pd_corsa_assign_device(sess_hdl, dev_tgt.device_id, DEVICE_THRIFT_PORT);
  
  /* BEGIN */
  p4_pd_corsa_local_table_set_default_action_drop_pkt(sess_hdl, dev_tgt,
        &entry_hdl);

  p4_pd_corsa_fib_table_set_default_action_drop_pkt(sess_hdl, dev_tgt,
        &entry_hdl);

  openflow_setup(argc, argv);

  /* END */

  p4_pd_corsa_remove_device(sess_hdl, dev_tgt.device_id);
  
  return 0;
}


