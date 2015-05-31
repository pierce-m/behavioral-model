#include <iostream>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>

#include "Runtime.h"

#include <pd/pd_tables.h>
#include <pd/pd_static.h>
#include <pd/pd.h>

#define DEVICE_THRIFT_PORT 9090

extern "C" {
    int openflow_setup(int argc, char* argv[]);
    void start_cpu_packet_handler();
}

int mask_to_prefix (uint32_t address) {
   int zero_bits;
   if(address == 0) return 0;
   for (zero_bits = 0; (address & 1) == 0; address >>= 1, zero_bits++);
   return (32 - zero_bits);
}

p4_pd_sess_hdl_t sess_hdl;
p4_pd_dev_target_t dev_tgt = {0, 0xFF};

void corsa_set_default_tables(p4_pd_sess_hdl_t sess_hdl,
        p4_pd_dev_target_t dev_tgt)
{
    p4_pd_entry_hdl_t entry_hdl;

    p4_pd_corsa_mac_table_set_default_action_drop_pkt(sess_hdl, dev_tgt,
            &entry_hdl);

    p4_pd_corsa_vlan_mpls_table_set_default_action_nop(sess_hdl, dev_tgt,
            &entry_hdl);

    p4_pd_corsa_vlan_table_set_default_action_drop_pkt(sess_hdl, dev_tgt,
            &entry_hdl);

    p4_pd_corsa_mpls_table_set_default_action_nop(sess_hdl, dev_tgt,
            &entry_hdl);

    p4_pd_corsa_ether_table_set_default_action_drop_pkt(sess_hdl, dev_tgt,
            &entry_hdl);

    p4_pd_corsa_cos_map_table_set_default_action_nop(sess_hdl, dev_tgt,
            &entry_hdl);

//    p4_pd_corsa_fib_table_set_default_action_drop_pkt(sess_hdl, dev_tgt,
    p4_pd_corsa_fib_table_set_default_action_nop(sess_hdl, dev_tgt,
            &entry_hdl);

    p4_pd_corsa_local_table_set_default_action_nop(sess_hdl, dev_tgt,
            &entry_hdl);
}


extern "C" {
    void local_table_add(void **entry)
    {
        p4_pd_entry_hdl_t entry_hdl;
        p4_pd_corsa_local_table_match_spec_t ms;

        ms.standard_metadata_egress_port = 125;
        p4_pd_corsa_local_table_table_add_with_send_to_controller(sess_hdl, dev_tgt, &ms, &entry_hdl);
        *(p4_pd_entry_hdl_t *)(entry) = entry_hdl;
    } 
    void local_table_mod(void *entry)
    {
        p4_pd_corsa_local_table_table_modify_with_send_to_controller(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
    }
    void table_delete(void *entry)
    {
        p4_pd_corsa_local_table_table_delete(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
    }

    void mac_table_add(uint8_t *mac, uint8_t *mac_mask, int pri, int cmd, void **entry)
    {
        p4_pd_entry_hdl_t entry_hdl;
        p4_pd_corsa_mac_table_match_spec_t ms;
        memcpy(ms.eth_dstAddr, mac, 6);
        if(cmd == 1)
            p4_pd_corsa_mac_table_table_add_with_drop_pkt(sess_hdl, dev_tgt, &ms, &entry_hdl);
        else
            p4_pd_corsa_mac_table_table_add_with_nop(sess_hdl, dev_tgt, &ms, &entry_hdl);
        *(p4_pd_entry_hdl_t *)(entry) = entry_hdl;
    }

    void mac_table_mod(void *entry, int cmd)
    {
        if(cmd == 1)
            p4_pd_corsa_mac_table_table_modify_with_drop_pkt(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
        else
            p4_pd_corsa_mac_table_table_modify_with_nop(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
    }

    void vlan_table_add(uint16_t vlan, uint16_t vlan_mask, int pri, int cmd, void **entry)
    {
        p4_pd_entry_hdl_t entry_hdl;
        p4_pd_corsa_vlan_table_match_spec_t ms;
        ms.vlan_vid = vlan;
        if(cmd == 1)
            p4_pd_corsa_vlan_table_table_add_with_drop_pkt(sess_hdl, dev_tgt, &ms, &entry_hdl);
        else
            p4_pd_corsa_vlan_table_table_add_with_vlan_valid(sess_hdl, dev_tgt, &ms, &entry_hdl);
        *(p4_pd_entry_hdl_t *)(entry) = entry_hdl;
    }

    void vlan_table_mod(void *entry, int cmd)
    {
        if(cmd == 1)
            p4_pd_corsa_vlan_table_table_modify_with_drop_pkt(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
        else
            p4_pd_corsa_vlan_table_table_modify_with_vlan_valid(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)entry);
    }

    void ether_table_add(uint16_t ethtype, uint16_t ethtype_mask, int pri, int cmd, void **entry)
    {
        p4_pd_entry_hdl_t entry_hdl;
        p4_pd_corsa_ether_table_match_spec_t ms;
        ms.eth_ethType = ethtype;
        if(cmd == 1) {
            p4_pd_corsa_ether_table_table_add_with_drop_pkt(sess_hdl, dev_tgt, &ms, &entry_hdl);
        }
        else if(cmd == 2) {
            p4_pd_corsa_ether_table_table_add_with_nop(sess_hdl, dev_tgt, &ms, &entry_hdl);
        }
        else {
            p4_pd_corsa_ether_table_table_add_with_send_to_controller(sess_hdl, dev_tgt, &ms, &entry_hdl);
        }
        *(p4_pd_entry_hdl_t *)(entry) = entry_hdl;
    }

    void ether_table_mod(void *entry, int cmd)
    {
        if(cmd == 1) {
            p4_pd_corsa_ether_table_table_modify_with_drop_pkt(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
        }
        else if(cmd == 2) {
            p4_pd_corsa_ether_table_table_modify_with_nop(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
        }
        else {
            p4_pd_corsa_ether_table_table_modify_with_send_to_controller(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
        }
    }

    void fib_table_add(uint32_t ipv4, uint32_t ipv4_mask, int pri, int cmd, int port, void **entry)
    {
        p4_pd_entry_hdl_t entry_hdl;
        p4_pd_corsa_fib_table_match_spec_t ms;
        p4_pd_corsa_fwd_next_hop_action_spec_t as;

        ms.ipv4_dstAddr = ipv4;
        ms.ipv4_dstAddr_prefix_length = mask_to_prefix(ipv4_mask);
printf("IP 0x%08x/%d\n", ms.ipv4_dstAddr, ms.ipv4_dstAddr_prefix_length); 
        if(cmd == 1)
            p4_pd_corsa_fib_table_table_add_with_drop_pkt(sess_hdl, dev_tgt, &ms, /*pri,*/ &entry_hdl);
        else {
            as.action_port = port;
            p4_pd_corsa_fib_table_table_add_with_fwd_next_hop(sess_hdl, dev_tgt, &ms, /*pri,*/ &as, &entry_hdl);
        }
        *(p4_pd_entry_hdl_t *)(entry) = entry_hdl;
    }

    void fib_table_mod(void *entry, int cmd, int port)
    {
        p4_pd_corsa_fwd_next_hop_action_spec_t as;
        if(cmd == 1)
            p4_pd_corsa_fib_table_table_modify_with_drop_pkt(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)&entry);
        else {
            as.action_port = port;
            p4_pd_corsa_fib_table_table_modify_with_fwd_next_hop(sess_hdl, dev_tgt.device_id, *(p4_pd_entry_hdl_t *)entry, &as);
        }
    }

}


int main(int argc, char **argv)
{
    start_cpu_packet_handler();

    p4_pd_init();

    p4_pd_client_init(&sess_hdl, 16);

    std::cerr << "session handle is " << sess_hdl << std::endl;


    /* P4 dependent initialization */
    p4_pd_corsa_init(sess_hdl, NULL);
    p4_pd_corsa_assign_device(sess_hdl, dev_tgt.device_id, DEVICE_THRIFT_PORT);


    /* BEGIN */
    corsa_set_default_tables(sess_hdl, dev_tgt);

    // forever loop
    openflow_setup(argc, argv);

    /* END */

    p4_pd_corsa_remove_device(sess_hdl, dev_tgt.device_id);

    return 0;
}


