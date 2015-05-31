/*
*   corsa.p4
*/


#define CPU_PORT 125

header_type  cpu_header_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;

        ether_type        : 16;

        fabric_qos         : 8;
        pad                : 1;
        pkt_version        : 2;
        type_              : 3;
        hdr_version        : 2;

        lif               : 16;
        bridge_domain     : 16;

        bypass_ingress    : 1;
        egress_queue      : 5;
        reserved          : 10;

        egress_port       : 16;
    }
}

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        ethType : 16;
    }
}


header_type vlan_t {
    fields {
        pcp : 3;
	    cfi : 1;
	    vid : 12;
	    ethType : 16;
    }
    //length  4;
    //max_length 4;
}


header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        ipv4_length : 16;
        id : 16 ;
        flags : 3;
        offset : 13;
        ttl : 8;
        protocol : 8;
        checksum : 16;
        srcAddr : 32;
        dstAddr : 32;
    }
    //length ihl * 4;
    //max_length 32;
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header cpu_header_t cpu;
header ethernet_t eth;
header vlan_t vlan;
header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.ipv4_length;
        ipv4.id;
        ipv4.flags;
        ipv4.offset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.checksum {
    verify ipv4_checksum if(ipv4.ihl == 5);
    update ipv4_checksum if(ipv4.ihl == 5);
}

header_type ingress_metadata_t {
    fields {
        packet_hit : 1;
        nhop : 16;
    }
}
metadata ingress_metadata_t md;

/*
  +------------------------------------------- 
    Define parser
  +------------------------------------------- 
*/


#define VLAN_TYPE 0x8100
#define IPV4_TYPE 0x0800
#define CPU_TYPE 0x0109


parser start {
    return parse_eth;
}


parser parse_eth {
    extract(eth);
    return select (eth.ethType) {
        VLAN_TYPE : parse_vlan;
        IPV4_TYPE : parse_ipv4;
        default : ingress;
    }
}


parser parse_cpu {
    extract(cpu);
    return ingress;
}

parser parse_vlan {
    extract(vlan);
    return ingress;
}

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}


action drop_pkt() {
    modify_field(md.packet_hit, 0);
    drop();
}

action nop() {
}

action broadcast_process() {
}

action unicast_process() {
}

action mac_miss() {
}

table mac_table {
    reads {
        eth.dstAddr : exact;
    }
    actions {
        drop_pkt; // default action
        nop;
    }
    size : 1024;
}

action mpls_process() {
}

table vlan_mpls_table {
    reads  {
        vlan.vid : exact;
    }
    actions {
        nop;
    }
    size : 4096;
}

action vlan_miss() {
}

action vlan_valid() {
}

table vlan_table {
    reads {
        vlan.vid : exact;
    }
    actions {
        drop_pkt; // default action
        vlan_valid;
        nop;
    }
    size : 4096;
}


action mpls_fwd() {
}

table mpls_table {
    actions {
        nop;
    }
    size : 1024;
}

action fwd_pkt(port) {
    // next table
    modify_field(standard_metadata.egress_port, port);
}

action send_to_controller() {
    // send to cpu
    modify_field(standard_metadata.egress_port, CPU_PORT);
}

table ether_table {
    reads {
        eth.ethType : exact;    // 0806 -> arp_ctl
                                // 0800 -> ip_fwd
    }
    actions {
        drop_pkt; // default action
        nop;
        send_to_controller;
    }
    size : 256;
}

action write_mac(mac) {
    modify_field(eth.dstAddr, mac);
}

table local_table {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        nop;
        send_to_controller;
        write_mac;
    }
    size : 256;
}

action fwd_next_hop(port) {
    modify_field(md.packet_hit, 1);
    modify_field(standard_metadata.egress_port, port);
}

table fib_table {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        nop;
        drop_pkt;
        fwd_next_hop;
    }
    size : 16384;
}

table cos_map_table {
    actions {
        nop;
    }
    size: 256;
}

control ingress {
    apply(mac_table);
    apply(vlan_mpls_table);
    apply(vlan_table);
    apply(mpls_table);
    apply(ether_table);
    apply(cos_map_table);
    apply(fib_table);
    apply(local_table);
}


