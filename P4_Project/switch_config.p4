/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 0x6;
const bit<16> SSH_DEFAULT_PORT = 0x16;
const bit<16> TYPE_GSS = 0x1212;
#define CPU_PORT 255
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
header GSS_t {
    bit<24> geoname_id;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
}

@controller_header("packet_in")
header packet_in_t {
    bit<24> geoname_id; //geoname_id
    bit<32> srcAddr;
}

@controller_header("packet_out")
header packet_out_t {
  bit<24> reason_id;
}

struct headers {
    packet_in_t  packetin;
    packet_out_t packetout;
    ethernet_t   ethernet;
    GSS_t         gss;
    ipv4_t       ipv4;
    tcp_t        tcp;
    }


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
	transition select(standard_metadata.ingress_port){
            CPU_PORT: parse_packet_out;
	           default: parse_ethernet;
        }
    }
    state parse_packet_out {
        packet.extract(hdr.packetout);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_GSS: parse_gss;
            default: accept;
        }
    }
    state parse_gss {
	     packet.extract(hdr.gss);
         transition parse_ipv4;
     }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
        TYPE_TCP: parse_tcp;
        default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
	       transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action secure_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table ipv4_lpm_for_ssh {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table secure_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            secure_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table firewall_exact {
        key = {
            hdr.gss.geoname_id: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    apply {
        if (hdr.tcp.isValid()){
            if (hdr.tcp.dstPort != SSH_DEFAULT_PORT){
                ipv4_lpm.apply();
            }
            else{
                ipv4_lpm_for_ssh.apply();
                if (standard_metadata.ingress_port == CPU_PORT) { //packet out
                    hdr.packetout.setInvalid();
                    secure_lpm.apply();
                }
                if (standard_metadata.egress_spec == CPU_PORT) { // packet in
                    hdr.packetin.setValid();
                    hdr.packetin.geoname_id= hdr.gss.geoname_id; //geoname_id
                    hdr.packetin.srcAddr=hdr.ipv4.srcAddr; //srcAddr
                }
                if (hdr.gss.isValid() && standard_metadata.ingress_port != CPU_PORT){
                    firewall_exact.apply();
                }
                if (!hdr.gss.isValid()){
                    drop();
                }
            }
        }
        else{
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    counter(1, CounterType.bytes) c;
    apply {
        if (hdr.ipv4.dstAddr== (bit<32>)1601104747 && standard_metadata.egress_port!=CPU_PORT){
            c.count(0);
        }
    }
}
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packetin);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.gss);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
