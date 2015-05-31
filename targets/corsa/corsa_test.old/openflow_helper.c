/*
*   openflow_helper.c
*/
// Openflow section
#include <OFConnectionManager/ofconnectionmanager_config.h>
#include <OFConnectionManager/ofconnectionmanager.h>
#include <indigo/of_connection_manager.h>
#include <indigo/port_manager.h>
#include <indigo/of_state_manager.h>
#include <indigo/assert.h>
#include <indigo/memory.h>
#include <SocketManager/socketmanager.h>
#include <OFStateManager/ofstatemanager.h>

#define CONTROLLER_IP "10.211.55.13"
#define CONTROLLER_IPV6 "::1"
#define CONTROLLER_IPV6_LINKLOCAL "fe80::b00b:4cff:fe2f:1fe3%lo"
#define CONTROLLER_PORT 6633


#define OK(op)  INDIGO_ASSERT((op) == INDIGO_ERROR_NONE)

#define VAR_OF_DESC_STR_T_INIT(var, val) \
    memcpy((uint8_t *)&(var), (uint8_t *)val, sizeof(var))

#define VAR_OF_SERIAL_NUM_T_INIT(var, val) \
    memcpy((uint8_t *)&(var), (uint8_t *)val, sizeof(var))

static ind_cxn_config_t cm_config;

/* Status change handler */
static int status_change_called;
    static void
cxn_status_change(indigo_cxn_id_t cxn_id,
        indigo_cxn_protocol_params_t *cxn_proto_params,
        indigo_cxn_state_t state,
        void *cookie)
{
    printf("Status change called\n");
    status_change_called = 1;
}

/* Return connection ID */
static indigo_cxn_protocol_params_t protocol_params;
static indigo_cxn_config_params_t config_params;

extern void ind_core_flow_add_handler(
        of_object_t *_obj,
        indigo_cxn_id_t cxn);
extern void
ind_core_flow_stats_request_handler(of_object_t *_obj, indigo_cxn_id_t cxn_id);
extern void
ind_core_port_stats_request_handler(of_object_t *_obj, indigo_cxn_id_t cxn_id);
extern void
ind_core_group_desc_stats_request_handler(of_object_t *_obj,
                                          indigo_cxn_id_t cxn_id);
extern void
ind_core_group_stats_request_handler(of_object_t *_obj,
                                     indigo_cxn_id_t cxn_id);


/* Table operations */

static indigo_error_t
op_entry_create(void *table_priv, indigo_cxn_id_t cxn_id,
                of_flow_add_t *obj, indigo_cookie_t flow_id, void **entry_priv)
{
    of_match_t match;
    uint16_t prio;

    printf("flow create called\n");
    *entry_priv = NULL;
    if (of_flow_add_match_get(obj, &match) < 0) {
        printf("unexpected failure in of_flow_add_match_get");
        return -1;
    }
    of_flow_add_priority_get(obj, &prio);

    printf("prio %d: DMAC %02x:%02x:%02x:%02x:%02x:%02x\n",  prio,
         match.fields.eth_dst.addr[0],match.fields.eth_dst.addr[1],match.fields.eth_dst.addr[2],match.fields.eth_dst.addr[3],match.fields.eth_dst.addr[4],match.fields.eth_dst.addr[5]);

    printf("in_port %d\n", match.fields.in_port);
    printf("vlan %d\n", match.fields.vlan_vid);
    printf("ip_dst 0x%08x\n", match.fields.ipv4_dst);
    printf("ip_dst_mask 0x%08x\n", match.masks.ipv4_dst);

    of_list_instruction_t instructions; 
    of_flow_add_instructions_bind(obj, &instructions); 
    of_object_t inst; 
    int loop_rv; 
    uint8_t table_id;
    of_list_action_t *actions;

    OF_LIST_INSTRUCTION_ITER(&instructions, &inst, loop_rv) { 
        printf("Instr: %d ", inst.object_id);
        switch( inst.object_id) {
            case OF_INSTRUCTION_GOTO_TABLE:
                of_instruction_goto_table_table_id_get( &inst, &table_id);
                printf("goto table %d\n", table_id);
                break;
            case OF_INSTRUCTION_APPLY_ACTIONS:
                actions = of_instruction_apply_actions_actions_get(&inst);
                if(actions) {
                    printf("apply action\n");
                }
                break;
            default:
                printf("unsupported\n");
                break;
        }
        /*
        if (inst.object_id == OF_INSTRUCTION_METER) { 
            of_instruction_meter_meter_id_get(&inst, &entry->meter); 
        } 
        */
        printf("\n");
    } 

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
op_entry_modify(void *table_priv, indigo_cxn_id_t cxn_id,
                void *entry_priv, of_flow_modify_t *obj)
{
    printf("flow modify called\n");
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
op_entry_delete(void *table_priv, indigo_cxn_id_t cxn_id,
                void *entry_priv, indigo_fi_flow_stats_t *flow_stats)
{
    printf("flow delete called\n");
    memset(flow_stats, 0, sizeof(*flow_stats));
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
op_entry_stats_get(void *table_priv, indigo_cxn_id_t cxn_id,
                   void *entry_priv, indigo_fi_flow_stats_t *flow_stats)
{
//    printf("flow stats get called\n");
    memset(flow_stats, 0, sizeof(*flow_stats));
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
op_entry_hit_status_get(void *table_priv, indigo_cxn_id_t cxn_id,
                        void *entry_priv, bool *hit_status)
{
    printf("flow hit status get called\n");
    *hit_status = false;
    return INDIGO_ERROR_NONE;
}

static indigo_core_table_ops_t mac_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t vlan_mpls_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t vlan_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t mpls_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t ether_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t cos_map_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t fib_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t unknown1_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t unknown2_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

static indigo_core_table_ops_t local_table_ops = {
    op_entry_create,
    op_entry_modify,
    op_entry_delete,
    op_entry_stats_get,
    op_entry_hit_status_get,
};

indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *of_packet_out)
{
    printf("packet out called\n");
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_port_features_get(of_features_reply_t *features)
{
    printf("port features get called\n");
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_fwd_forwarding_features_get(of_features_reply_t *features)
{
    printf("forwarding features get called\n");
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_port_modify(of_port_mod_t *port_mod)
{
    printf("port mod called\n");
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_port_stats_get(of_port_stats_request_t *request,
                      of_port_stats_reply_t **reply_ptr)
{
    *reply_ptr = of_port_stats_reply_new(request->version);
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_port_queue_config_get(of_queue_get_config_request_t *request,
                             of_queue_get_config_reply_t **reply_ptr)
{
    printf("queue config get called\n");
    *reply_ptr = of_queue_get_config_reply_new(request->version);
    return INDIGO_ERROR_NONE;
}


indigo_error_t
indigo_port_queue_stats_get(of_queue_stats_request_t *request,
                            of_queue_stats_reply_t **reply_ptr)
{

    printf("queue stats get called\n");
    *reply_ptr = of_queue_stats_reply_new(request->version);
    return INDIGO_ERROR_NONE;
}


indigo_error_t
indigo_port_experimenter(of_experimenter_t *experimenter,
                         indigo_cxn_id_t cxn_id)
{
    printf("port experimenter called\n");
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_fwd_experimenter(of_experimenter_t *experimenter,
                        indigo_cxn_id_t cxn_id)
{
    printf("port experimenter called\n");
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_port_interface_list(indigo_port_info_t **list)
{
    *list = NULL;
    return INDIGO_ERROR_NONE;
}

void
indigo_port_interface_list_destroy(indigo_port_info_t *list)
{
}

indigo_error_t indigo_port_desc_stats_get(
    of_port_desc_stats_reply_t *port_desc_stats_reply)
{
    printf("port desc stats get called");
    return INDIGO_ERROR_NONE;
}

void
indigo_fwd_pipeline_get(of_desc_str_t pipeline)
{
    printf("fwd switch pipeline get");
    strcpy(pipeline, "some_pipeline");
}

indigo_error_t
indigo_fwd_pipeline_set(of_desc_str_t pipeline)
{
    printf("fwd switch pipeline set: %s", pipeline);
    return INDIGO_ERROR_NONE;
}

void
indigo_fwd_pipeline_stats_get(of_desc_str_t **pipeline, int *num_pipelines)
{
    printf("fwd switch pipeline stats get");
    *num_pipelines = 0;
}



static int
setup_cxn(char *ip_addr, unsigned int port)
{
    indigo_controller_id_t id;

    config_params.version = OF_VERSION_1_3;

    protocol_params.tcp_over_ipv4.protocol = INDIGO_CXN_PROTO_TCP_OVER_IPV4;
    sprintf(protocol_params.tcp_over_ipv4.controller_ip, "%s", ip_addr);
    protocol_params.tcp_over_ipv4.controller_port = port;

    OK(indigo_controller_add(&protocol_params, &config_params, &id));

    return id;
}

    int
setup_cxn_ipv6(char *ip_addr, unsigned int port)
{
    indigo_controller_id_t id;

    config_params.version = OF_VERSION_1_3;

    protocol_params.tcp_over_ipv6.protocol = INDIGO_CXN_PROTO_TCP_OVER_IPV6;
    sprintf(protocol_params.tcp_over_ipv6.controller_ip, "%s", ip_addr);
    protocol_params.tcp_over_ipv6.controller_port = port;

    OK(indigo_controller_add(&protocol_params, &config_params, &id));

    return id;
}

    int
setup_cxn_ipv6_linklocal(char *ip_addr, unsigned int port)
{
    indigo_controller_id_t id;

    config_params.version = OF_VERSION_1_0;

    protocol_params.tcp_over_ipv6.protocol = INDIGO_CXN_PROTO_TCP_OVER_IPV6;
    sprintf(protocol_params.tcp_over_ipv6.controller_ip, "%s", ip_addr);
    protocol_params.tcp_over_ipv6.controller_port = port;

    OK(indigo_controller_add(&protocol_params, &config_params, &id));

    return id;
}

static int got_cxn_msg;

void
cxn_msg_rx(indigo_cxn_id_t cxn_id, of_object_t *obj)
{
    uint32_t xid;
    printf("Got msg from %d: type %d\n", cxn_id, obj->object_id);

    switch(obj->object_id) {
        /* Just respond to echo request */
        case OF_ECHO_REQUEST:
            {
                of_echo_request_t *echo;
                of_echo_reply_t *reply;
                of_octets_t data;

                echo = (of_echo_request_t *)obj;
                of_echo_request_xid_get(echo, &xid);
                printf("Respond to echo with xid 0x%x\n", xid);
                if ((reply = of_echo_reply_new(echo->version)) == NULL) {
                    printf("Could not allocate echo response obj\n");
                    goto done;
                }

                of_echo_request_data_get(echo, &data);
                if (data.bytes) {
                    OK(of_echo_reply_data_set(reply, &data));
                }

                of_echo_reply_xid_set(reply, xid);

                indigo_cxn_send_controller_message(cxn_id, reply);
            }
            break;
            /* respond to features request */
        case OF_FEATURES_REQUEST:
            {
                of_features_request_t *req;
                of_features_reply_t *reply;

                req = (of_features_request_t *)obj;
                of_features_request_xid_get(req, &xid);
                printf("Respond to features_request with xid 0x%x\n", xid);
                if ((reply = of_features_reply_new(req->version)) == NULL) {
                    printf("Could not allocate features_reply obj\n");
                    goto done;
                }

                if (obj->version >= OF_VERSION_1_3) {
                    uint8_t auxiliary_id;
                    indigo_cxn_get_auxiliary_id(cxn_id, &auxiliary_id);
                    of_features_reply_auxiliary_id_set(reply, auxiliary_id);
                    printf("Populating aux_id %d\n", auxiliary_id);
                    // set DPID to 2 (for now 
                    of_features_reply_datapath_id_set(reply, 2);
                }

                /* FIXME populate anything else? */
                of_features_reply_xid_set(reply, xid);

                indigo_cxn_send_controller_message(cxn_id, reply);
            }
            break;
        case OF_PORT_DESC_STATS_REQUEST:
            {
                of_port_desc_stats_request_t *req = (of_port_desc_stats_request_t  *)obj;
                of_port_desc_stats_reply_t *reply;

                /* Generate a port_desc_stats reply and send to controller */
                if ((reply = of_port_desc_stats_reply_new(obj->version)) == NULL) {
                    AIM_DIE("Failed to allocate port_desc_stats reply message");
                }

                of_port_desc_stats_request_xid_get(req, &xid);
                of_port_desc_stats_reply_xid_set(reply, xid);
                //        of_desc_stats_reply_dp_desc_set( obj, dp_desc);
                //    indigo_port_desc_stats_get(reply);

                indigo_cxn_send_controller_message(cxn_id, reply);
            }
            break;
        case OF_SET_CONFIG:
            {
                // skip for now
            }
            break;
        case OF_GET_CONFIG_REQUEST:
            {
                of_get_config_request_t *req = (of_get_config_request_t *)obj;
                of_get_config_reply_t *reply;

                /* Generate a port_desc_stats reply and send to controller */
                if ((reply = of_get_config_reply_new(obj->version)) == NULL) {
                    AIM_DIE("Failed to allocate get_config reply message");
                }

                of_get_config_request_xid_get(req, &xid);
                of_get_config_reply_xid_set(reply, xid);

                indigo_cxn_send_controller_message(cxn_id, reply);
            }
            break;

        case OF_DESC_STATS_REQUEST:
            {
                of_desc_stats_request_t *req = (of_desc_stats_request_t  *)obj;
                of_desc_stats_reply_t *reply;
                of_desc_str_t desc_str;
                of_serial_num_t ser_num;


                /* Generate a port_desc_stats reply and send to controller */
                if ((reply = of_desc_stats_reply_new(obj->version)) == NULL) {
                    AIM_DIE("Failed to allocate desc_stats reply message");
                }

                VAR_OF_DESC_STR_T_INIT(desc_str, "p4lang");
                of_desc_stats_reply_mfr_desc_set(reply, desc_str);

                VAR_OF_DESC_STR_T_INIT(desc_str, "corsa.p4");
                of_desc_stats_reply_hw_desc_set(reply, desc_str);

                VAR_OF_DESC_STR_T_INIT(desc_str, "0.1");
                of_desc_stats_reply_sw_desc_set(reply, desc_str);

                VAR_OF_SERIAL_NUM_T_INIT(ser_num, "1");
                of_desc_stats_reply_serial_num_set(reply, ser_num);

                VAR_OF_DESC_STR_T_INIT(desc_str, "p4");
                of_desc_stats_reply_dp_desc_set(reply, desc_str);

                of_desc_stats_request_xid_get(req, &xid);
                of_desc_stats_reply_xid_set(reply, xid);

                indigo_cxn_send_controller_message(cxn_id, reply);
            }
            break;
        case OF_FLOW_ADD:
            {
                ind_core_flow_add_handler(obj, cxn_id);
            }
            break;
        case OF_FLOW_STATS_REQUEST:
            ind_core_flow_stats_request_handler(obj, cxn_id);
#if 0
            {
                of_flow_stats_request_t *req = (of_flow_stats_request_t *)obj;
                of_flow_stats_reply_t *reply;
                if ((reply = of_flow_stats_reply_new(obj->version)) == NULL) {
                    AIM_DIE("Failed to allocate flow_stats reply message");
                }

                of_flow_stats_reply_xid_get(req, &xid);
                of_flow_stats_reply_xid_set(reply, xid);
                //                of_flow_stats_reply_flags_set(reply, 1);

                // for each flow send the stats

                // of_flow_stats_reply_entries_set(reply, repiles);(

                indigo_cxn_send_controller_message(cxn_id, reply);
            }
#endif
            break;
        case OF_GROUP_STATS_REQUEST:
            ind_core_group_stats_request_handler(obj, cxn_id);
#if 0
            {
                of_group_stats_request_t *req = (of_group_stats_request_t  *)obj;
                of_group_stats_reply_t *reply;
                if ((reply = of_group_stats_reply_new(obj->version)) == NULL) {
                    AIM_DIE("Failed to allocate group_stats reply message");
                }
                of_group_stats_reply_xid_get(req, &xid);
                of_group_stats_reply_xid_set(reply, xid);

                //                of_group_stats_reply_flags_set(reply, 1);

                indigo_cxn_send_controller_message(cxn_id, reply);

            }
#endif
            break;
        case OF_GROUP_DESC_STATS_REQUEST:
            ind_core_group_desc_stats_request_handler(obj, cxn_id);
#if 0
            {
                of_group_desc_stats_request_t *req = (of_group_desc_stats_request_t  *)obj;
                of_group_desc_stats_reply_t *reply;
                if ((reply = of_group_desc_stats_reply_new(obj->version)) == NULL) {
                    AIM_DIE("Failed to allocate group_desc_stats reply message");
                }

                of_group_desc_stats_reply_xid_get(req, &xid);
                of_group_desc_stats_reply_xid_set(reply, xid);

                //                of_group_desc_stats_reply_flags_set(reply, 1);

                indigo_cxn_send_controller_message(cxn_id, reply);

            }
#endif
            break;
        case OF_PORT_STATS_REQUEST:
            ind_core_port_stats_request_handler(obj, cxn_id);
#if 0
            {
                of_port_stats_request_t *req = (of_port_stats_request_t  *)obj;
                of_port_stats_reply_t *reply;
                if ((reply = of_port_stats_reply_new(obj->version)) == NULL) {
                    AIM_DIE("Failed to allocate flow_stats reply message");
                }

                of_port_stats_reply_xid_get(req, &xid);
                of_port_stats_reply_xid_set(reply, xid);

                of_port_stats_reply_flags_set(reply, 1);

                indigo_cxn_send_controller_message(cxn_id, reply);

            }
#endif
            break;
        default:
            printf("Not supported yet\n");
            break;
    }

done:
    got_cxn_msg = 1;
}

#if 1
/*
 * Implement Forwarding function
 */
    void
indigo_core_receive_controller_message(indigo_cxn_id_t cxn_id,
        of_object_t *obj)
{
    cxn_msg_rx(cxn_id, obj);
}
#endif

int openflow_setup(int argc, char* argv[])
{
    int controller_id;
    ind_soc_config_t config; /* Currently ignored */
    ind_core_config_t core;

    memset(&config, 0, sizeof(config));
    OK(ind_soc_init(&config));

    OK(ind_cxn_init(&cm_config));

    OK(indigo_cxn_status_change_register(cxn_status_change, NULL));

    OK(ind_core_init(&core));

    OK(ind_cxn_enable_set(1));

    indigo_core_table_register(0, "mac_table", &mac_table_ops, NULL);
    indigo_core_table_register(1, "vlan_mpls_table", &vlan_mpls_table_ops, NULL);
    indigo_core_table_register(2, "vlan_table", &vlan_table_ops, NULL);
    indigo_core_table_register(3, "mpls_table", &mpls_table_ops, NULL);
    indigo_core_table_register(4, "ether_table", &ether_table_ops, NULL);
    indigo_core_table_register(5, "cos_map_table", &cos_map_table_ops, NULL);
    indigo_core_table_register(6, "fib_table", &fib_table_ops, NULL);
    indigo_core_table_register(7, "unknown1_table", &unknown1_table_ops, NULL);
    indigo_core_table_register(8, "unknown2_table", &unknown2_table_ops, NULL);
    indigo_core_table_register(9, "local_table", &local_table_ops, NULL);

    if(argc > 2) {
        INDIGO_ASSERT((controller_id = setup_cxn(argv[1], atoi(argv[2]))) >= 0);
    }
    else {
        INDIGO_ASSERT((controller_id = setup_cxn(CONTROLLER_IP, CONTROLLER_PORT)) >= 0);
    }
    //    INDIGO_ASSERT(setup_cxn_ipv6(CONTROLLER_IPV6, CONTROLLER_PORT) >= 0);
    //    INDIGO_ASSERT(setup_cxn_ipv6_linklocal(CONTROLLER_IPV6_LINKLOCAL, port) >= 0);

    OK(ind_soc_select_and_run(-1));

    OK(indigo_controller_remove(controller_id));

    OK(ind_cxn_enable_set(0));
    OK(ind_cxn_finish());

    return 0;
}

