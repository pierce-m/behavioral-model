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

#include <pthread.h>


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
#define MAX_NUM_TABLES 10

struct corsa_table {
    int table_id;
};

struct corsa_table my_table[MAX_NUM_TABLES];

const char *table_name[] = {
    "MAC",
    "MPLS_VLAN",
    "VLAN",
    "MPLS",
    "ETHER",
    "COS_MAP",
    "FIB",
    "UNK1",
    "UNK2",
    "LOCAL",
    ""
};

static void print_match_fields(int table_id, of_match_t *match)
{
    switch(table_id) {
        case 0: // MAC
            printf("DMAC %02x:%02x:%02x:%02x:%02x:%02x ",
                    match->fields.eth_dst.addr[0],match->fields.eth_dst.addr[1],match->fields.eth_dst.addr[2],match->fields.eth_dst.addr[3],match->fields.eth_dst.addr[4],match->fields.eth_dst.addr[5]);

            printf("DMAC mask %02x:%02x:%02x:%02x:%02x:%02x\n",
                    match->masks.eth_dst.addr[0],match->masks.eth_dst.addr[1],match->masks.eth_dst.addr[2],match->masks.eth_dst.addr[3],match->masks.eth_dst.addr[4],match->masks.eth_dst.addr[5]);

            break;
        case 1: // VLAN MPLS
        case 2: // VLAN
            printf("vlan %d ", match->fields.vlan_vid);
            printf("vlan_mask 0x%x\n", match->masks.vlan_vid);
            break;
        case 4: // Ether
            printf("eth_type 0x%08x ", match->fields.eth_type);
            printf("eth_type_mask 0x%08x\n", match->masks.eth_type);
            break;
        case 5: // COS
            break;
        case 6: // FIB
            printf("ip_dst 0x%08x ", match->fields.ipv4_dst);
            printf("ip_dst_mask 0x%08x\n", match->masks.ipv4_dst);
            break;
        case 9: // LOCAL
            break;
    }
}

typedef enum {
    ADD=0,
    MOD=1,
    DEL=2
} table_ops_t;


typedef enum {
    NONE=0,
    DROP,
    GOTO,
    OUTPUT,
    SET_FIELD
} table_cmd_t;


const char *cmd_name[] = {
    "NONE",
    "DROP",
    "GOTO",
    "OUTPUT",
    "SET_FIELD",
    ""
};

void process_action(of_object_t *inst, table_cmd_t *cmd, int *param)
{
    *cmd = DROP;
    //    printf("Instr: %d\n", inst->object_id);
    switch( inst->object_id) {
        case OF_INSTRUCTION_GOTO_TABLE:
            {
                uint8_t table_id;
                of_instruction_goto_table_table_id_get( inst, &table_id);
                printf("Goto table %s[%d]\n", table_name[table_id], table_id);
                *cmd = GOTO;
            }
            break;
        case OF_INSTRUCTION_APPLY_ACTIONS:
            {
                of_list_action_t *actions;
                actions = of_instruction_apply_actions_actions_get(inst);
                if(actions) {
                    printf("apply action\n");
                    of_object_t elt;
                    of_action_output_t *output;
                    of_action_set_field_t *set_field;
                    set_field = &elt;
                    output = &elt;
                    of_list_action_first(actions, &elt);
                    do {
                        // 
                        switch(elt.object_id) {
                            case OF_ACTION_OUTPUT:
                                {
                                    of_port_no_t port;
                                    of_action_output_port_get(output, &port);
                                    printf("Output set 0x%x\n", port);
                                    *cmd = OUTPUT;
                                    *param = port;
                                }
                                break;
                            case OF_ACTION_SET_FIELD:
                                {
                                    printf("Set field\n");
                                    *cmd = SET_FIELD;
                                }
                                break;
                            default:
                                {
                                    printf("Unsup obj id %d\n", elt.object_id);
                                }
                                break;
                        }
                    } while(of_list_action_next(actions, &elt) >= 0);
                }
                of_list_action_delete(actions);
            }
            break;
        default:
            printf("unsupported\n");
            break;
    }
}


// placeholder for autogeneration

extern void table_delete(void *entry);

extern void local_table_add(void **entry);
extern void local_table_mod(void *entry);

extern void mac_table_add(uint8_t *mac, uint8_t *mac_mask, int pri, int cmd, void **entry);
extern void mac_table_mod(void *entry, int cmd);

extern void vlan_table_add(uint16_t vlan, uint16_t vlan_mask, int pri, int cmd, void **entry);
extern void vlan_table_mod(void *entry, int cmd);

extern void ether_table_add(uint16_t ethtype, uint16_t ethtype_mask, int pri, int cmd, void **entry);
extern void ether_table_mod(void *entry, int cmd);


extern void fib_table_add(uint32_t ipv4, uint32_t ipv4_mask, int eth_type,  int pri, int cmd, int port, void **entry);
extern void fib_table_mod(void *entry, int cmd, int param);



void table_op(table_ops_t op, int table, of_match_t *match, int pri, int cmd, int param, void **entry)
{
    printf("Table %s action %s\n", (op == ADD) ? "ADD" : (op==MOD) ? "MOD" : "DEL", cmd_name[cmd]);
    switch(table) {
        case 0: // mac
            switch(op) {
                case ADD:
                    mac_table_add(match->fields.eth_dst.addr, match->masks.eth_dst.addr, pri, cmd, entry);
                    break;
                case MOD:
                    mac_table_mod(*entry, cmd);
                    break;
                case DEL:
                    table_delete(*entry);
                    break;
            }
            break;
        case 2: // vlan
            switch(op) {
                case ADD:
                    vlan_table_add(match->fields.vlan_vid, match->masks.vlan_vid, pri, cmd, entry);
                    break;
                case MOD:
                    vlan_table_mod(*entry, cmd);
                    break;
                case DEL:
                    table_delete(*entry);
                    break;
            }
            break;

        case 4: // ether
            switch(op) {
                case ADD:
                    ether_table_add(match->fields.eth_type, match->masks.eth_type, pri, cmd, entry);
                    break;
                case MOD:
                    ether_table_mod(*entry, cmd);
                    break;
                case DEL:
                    table_delete(*entry);
                    break;
            }
            break;

        case 6: // fib
            switch(op) {
                case ADD:
                    fib_table_add(match->fields.ipv4_dst, match->masks.ipv4_dst, match->fields.eth_type, pri, cmd, param, entry);
                    break;
                case MOD:
                    fib_table_mod(*entry, cmd, param);
                    break;
                case DEL:
                    table_delete(*entry);
                    break;
            }
            break;

        case 9: // local
            switch(op) {
                case ADD:
                    local_table_add(entry);
                    break;
                case MOD:
                    local_table_mod(*entry);
                    break;
                case DEL:
                    table_delete(*entry);
                    break;
            }
            break;

        default:
            break;
    }
}


    static indigo_error_t
op_entry_create(void *table_priv, indigo_cxn_id_t cxn_id,
        of_flow_add_t *obj, indigo_cookie_t flow_id, void **entry_priv)
{
    of_match_t match;
    uint16_t prio;
    struct corsa_table *table = (struct corsa_table *)table_priv;

    printf("\nflow create");
    if(!table) {
        return -1;
    }
    printf(" on table %s\n", table_name[table->table_id]);
    *entry_priv = NULL;
    if (of_flow_add_match_get(obj, &match) < 0) {
        printf("unexpected failure in of_flow_add_match_get");
        return -1;
    }
    of_flow_add_priority_get(obj, &prio);

    print_match_fields(table->table_id, &match);

    of_list_instruction_t instructions; 
    of_flow_add_instructions_bind(obj, &instructions); 
    of_object_t inst; 
    int loop_rv; 
    table_cmd_t cmd=DROP;
    int param;

    OF_LIST_INSTRUCTION_ITER(&instructions, &inst, loop_rv) { 
        process_action(&inst, &cmd, &param);
    } 

    table_op(ADD, table->table_id, &match, prio, cmd, param, entry_priv);

    return INDIGO_ERROR_NONE;
}

    static indigo_error_t
op_entry_modify(void *table_priv, indigo_cxn_id_t cxn_id,
        void *entry_priv, of_flow_modify_t *obj)
{
    of_match_t match;
    struct corsa_table *table = (struct corsa_table *)table_priv;
    if(!table)
        return -1;
    printf("\nflow modify on table %s\n", table_name[table->table_id]);
    if (of_flow_add_match_get(obj, &match) < 0) {
        printf("unexpected failure in of_flow_add_match_get");
        return -1;
    }
    print_match_fields(table->table_id, &match);
    of_list_instruction_t instructions; 
    of_flow_modify_instructions_bind(obj, &instructions); 
    of_object_t inst; 
    int loop_rv; 
    table_cmd_t cmd=DROP;
    int param;

    OF_LIST_INSTRUCTION_ITER(&instructions, &inst, loop_rv) { 
        process_action(&inst, &cmd, &param);
    } 

    table_op(MOD, table->table_id, &match, 0, cmd, param, &entry_priv);

    return INDIGO_ERROR_NONE;
}

    static indigo_error_t
op_entry_delete(void *table_priv, indigo_cxn_id_t cxn_id,
        void *entry_priv, indigo_fi_flow_stats_t *flow_stats)
{
    int cmd=DROP, param=0;
    of_match_t match;
    struct corsa_table *table = (struct corsa_table *)table_priv;
    if(!table)
        return -1;
    printf("\nflow delete %s\n", table_name[table->table_id]);
    table_op(DEL, table->table_id, &match, 0, cmd, param, &entry_priv);
    memset(flow_stats, 0, sizeof(*flow_stats));
    return INDIGO_ERROR_NONE;
}

    static indigo_error_t
op_entry_stats_get(void *table_priv, indigo_cxn_id_t cxn_id,
        void *entry_priv, indigo_fi_flow_stats_t *flow_stats)
{
    //    printf("\nflow stats get called\n");
    memset(flow_stats, 0, sizeof(*flow_stats));
    return INDIGO_ERROR_NONE;
}

    static indigo_error_t
op_entry_hit_status_get(void *table_priv, indigo_cxn_id_t cxn_id,
        void *entry_priv, bool *hit_status)
{
    printf("\nflow hit status get called\n");
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
    //    printf("Got msg from %d: type %d\n", cxn_id, obj->object_id);

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
            printf("Not supported yet %d\n", obj->object_id);
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

indigo_core_listener_result_t
packet_in(void *arg)
{
    return 0;
}

int openflow_setup(int argc, char* argv[])
{
    int controller_id;
    ind_soc_config_t config; /* Currently ignored */
    ind_core_config_t core;
    int i=0;

    memset(&config, 0, sizeof(config));
    OK(ind_soc_init(&config));

    OK(ind_cxn_init(&cm_config));

    OK(indigo_cxn_status_change_register(cxn_status_change, NULL));
    /*
    OK(indigo_core_packet_in_listener_register(
        (indigo_core_packet_in_listener_f)packet_in));
    */

    OK(ind_core_init(&core));

    OK(ind_cxn_enable_set(1));

    for(i=0;i<MAX_NUM_TABLES;i++) {
        my_table[i].table_id = i;
    }

    ind_core_enable_set(1);

    indigo_core_table_register(0, "mac_table", &mac_table_ops, &my_table[0]);
    indigo_core_table_register(1, "vlan_mpls_table", &vlan_mpls_table_ops, &my_table[1]);
    indigo_core_table_register(2, "vlan_table", &vlan_table_ops, &my_table[2]);
    indigo_core_table_register(3, "mpls_table", &mpls_table_ops, &my_table[3]);
    indigo_core_table_register(4, "ether_table", &ether_table_ops, &my_table[4]);
    indigo_core_table_register(5, "cos_map_table", &cos_map_table_ops, &my_table[5]);
    indigo_core_table_register(6, "fib_table", &fib_table_ops, &my_table[6]);
    indigo_core_table_register(7, "unknown1_table", &unknown1_table_ops, &my_table[7]);
    indigo_core_table_register(8, "unknown2_table", &unknown2_table_ops, &my_table[8]);
    indigo_core_table_register(9, "local_table", &local_table_ops, &my_table[9]);

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


#if 1
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
// CPU port handler
pthread_t cpu_handler_thread;

static const char *cpu_port="veth251";
static int cpu_port_fd;
static int cpu_port_index;

static void handle_cpu_packet()
{
    int ret, fd, i;
    static unsigned char in_buf[10000];
    static unsigned char out_buf[10000];

    // read packet from cpu port
    fd = cpu_port_fd;
    while((ret = read(fd, in_buf, sizeof(in_buf))) > 0) {
        if (0) {
            for(i = 0; i < ret;) {
                printf("%02X", (unsigned char)in_buf[i]);
                i++;
                if (i && ((i % 16) == 0))  {
                    printf("\n");
                } else if (i && ((i % 8) == 0)) {
                    printf("  ");
                } else {
                    printf(" ");
                }
            }
            printf("\n\n");
        }
        // copy from in_buf to out_buf and set ret to length valid in out_buf
        memcpy(out_buf, in_buf, ret); // TODO skip cpu header  later
        {
            of_packet_in_t *packet_in = of_packet_in_new(OF_VERSION_1_0);
            of_octets_t octets = {.data = out_buf, .bytes = ret};
            of_packet_in_xid_set(packet_in, 0xfffffffe);
            of_packet_in_buffer_id_set(packet_in, 0x1234);
            of_packet_in_total_len_set(packet_in, ret);
            of_packet_in_in_port_set(packet_in, 1); // derive from packet in_buf

            int val = of_packet_in_data_set(packet_in, &octets);
            if(val == 0)
                indigo_core_packet_in(packet_in);
        }
    }
}
void *cpu_packet_handler(void *arg)
{
    // initialize raw socket
    if ((cpu_port_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("failed to open raw socket");
        exit(1);
    }

    // initialize cpu port
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, cpu_port, 9);
    if (ioctl(cpu_port_fd, SIOCGIFINDEX, (void *)&ifr) < 0) {
        perror("failed to get ifindex of cpu interface");
        exit(1);
    }
    cpu_port_index = ifr.ifr_ifindex;

    // bind to cpu port
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = cpu_port_index;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(cpu_port_fd, (struct sockaddr *)&addr,
             sizeof(struct sockaddr_ll)) < 0) {
        perror("bind to cpu interface failed");
        exit(1);
    }

    // set cpu port to be non-blocking
    int sock_flags = fcntl(cpu_port_fd, F_GETFL, 0);
    if (fcntl(cpu_port_fd, F_SETFL, sock_flags | O_NONBLOCK) < 0) {
        perror("f_setfl on cpu interface failed");
        exit(1);
    }


    // loop to get CPU packets and Punt to controller

    while(1) {
        int ret, nfds = 0;
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(cpu_port_fd, &read_fds);
        nfds++;

        ret = select(cpu_port_fd+1, &read_fds, NULL, NULL, NULL);
        if (ret == -1) {
            perror("select");
            return NULL;
        } else if (ret == 0) {
        } else {
            if (FD_ISSET(cpu_port_fd, &read_fds)) {
                handle_cpu_packet();
            }
        }
    }
}


void start_cpu_packet_handler()
{
    pthread_create(&cpu_handler_thread, NULL,
                       cpu_packet_handler, NULL);
}

#endif

