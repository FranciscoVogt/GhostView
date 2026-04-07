#include <tna.p4>

#include "sumBytes.p4"


/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_REC = 16w0x9966;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;



const ether_type_t ETHERTYPE_MONITOR = 0x1234;

#define FLOWS_MONITORING 15000



    /***********************  H E A D E R S  ************************/


header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}


header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    bit<48> hwSrcAddr;
    bit<32> protoSrcAddr;
    bit<48> hwDstAddr;
    bit<32> dest_ip;
}



header monitor_inst_h {
	 bit<32> index_flow; // index of the flow to collect the informations
	 bit<32> index_port; // index of the port to collect the informations
	 bit<9> port;		// port to forward the packet
	 bit<7> padding;
}//10 bytes

header monitor_h {
	bit<64> bytes_flow;
	bit<64> bytes_port;
	bit<48> timestamp;
	bit<9> port;
	bit<7> padding;
	bit<16> pktLen;


	bit<32> qID_port;
	bit<32> qDepth_port;
	bit<32> qTime_port;


	bit<32> qID_flow;
	bit<32> qDepth_flow;
	bit<32> qTime_flow;

}


struct headers {
    pktgen_timer_header_t timer;
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    monitor_inst_h 			mon_inst;
    ipv4_h       ipv4;
    monitor_h				monitor;
	udp_h			udp;
}


struct empty_header_t {}

struct empty_metadata_t {}

struct my_ingress_metadata_t {
    

}


struct my_egress_metadata_t {
	bit<32> qID;
	bit<32> qDepth;
	bit<32> qTime;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


parser SwitchIngressParser(
       packet_in packet, 
       out headers hdr, 
       out my_ingress_metadata_t md,
       out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        //pktgen_timer_header_t pktgen_pd_hdr = packet.lookahead<pktgen_timer_header_t>();
        
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_VLAN:  parse_vlan;
            ETHERTYPE_MONITOR: parse_monitor;
            default: accept;
        }
    }

    state parse_monitor {
		packet.extract(hdr.mon_inst);
		transition parse_ipv4;
	}
    
    state parse_vlan {
        packet.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
		
		transition select(hdr.ipv4.protocol) {
            17: parse_udp; // UDP
            default: accept; 
        }
        //transition accept;
    }

	state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }


}


control SwitchIngressDeparser(
        packet_out pkt,
        inout headers hdr,
        in my_ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                        hdr.ipv4.version,
                        hdr.ipv4.ihl,
                        hdr.ipv4.diffserv,
                        hdr.ipv4.total_len,
                        hdr.ipv4.identification,
                        hdr.ipv4.flags,
                        hdr.ipv4.ttl,
                        hdr.ipv4.protocol,
                        hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr
                    });

        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout headers hdr, 
        inout my_ingress_metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    action send(bit<9> port) {        
        ig_intr_tm_md.ucast_egress_port = port;
		   
    }


    table forward {
        key = {
            hdr.ipv4.dst_addr        : exact;

        }
        actions = {
            send;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 50000;
    }

    apply {
            //forward the packet
            forward.apply();

    }
}

// egress monitoring part

parser SwitchEgressParser(
	packet_in packet,
	out headers hdr,
	out my_egress_metadata_t eg_md,
	out egress_intrinsic_metadata_t eg_intr_md) {
	
	state start {
		packet.extract(eg_intr_md);
		transition parse_ethernet;
	}
	
	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_IPV4:  parse_ipv4;
			ETHERTYPE_VLAN:  parse_vlan;
			ETHERTYPE_MONITOR: parse_monitor;
			default: accept;
		}
	}

	state parse_monitor {
		packet.extract(hdr.mon_inst);
        packet.extract(hdr.ipv4);
		packet.extract(hdr.monitor);	// I extract to use the empty size in the packet
		transition accept;
	
	}

	state parse_vlan {
		packet.extract(hdr.vlan_tag);
		transition select(hdr.vlan_tag.ether_type) {
			ETHERTYPE_IPV4:  parse_ipv4;
			default: accept;
		}
	}
	
	state parse_ipv4 {
        packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
            17: parse_udp; // UDP
            default: accept; 
        }
        //transition accept;
    }

	state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control SwitchEgress(
	inout headers hdr,
	inout my_egress_metadata_t eg_md,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
	inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
	

	Add_64_64(FLOWS_MONITORING) byte_count_port;
	Add_64_64(FLOWS_MONITORING) byte_count_flow;
	
	
	//hashing for flows
	Hash<bit<12>>(HashAlgorithm_t.CRC32) hTableIndex;

	bit<32> flowIndex;
	bit<32> portIndex;

	bit<32> qID;
	bit<32> qDepth;
	bit<32> qTime;

	bit<64> dummy = 0;
		

	bit<32> d1=0;
	bit<32> d2=0;
	bit<32> d3=0;


	/* save the queueID that packet passes (flow saving) */
	Register<bit<32>, reg_index_t>(FLOWS_MONITORING) reg_queueID_flow;
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_queueID_flow) write_id_flow = {
		void apply(inout bit<32> value, out bit<32> result) {			
			value = eg_md.qID;
		}
	};
	
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_queueID_flow) read_id_flow = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = eg_md.qID; //comentar			
			result = value;
		}
	};
	
	/* save the dequeue depth that packet passes (flow saving)*/
	Register<bit<32>, reg_index_t>(FLOWS_MONITORING) reg_queueDepth_flow;
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_queueDepth_flow) write_depth_flow = {
		void apply(inout bit<32> value, out bit<32> result) {		
			value = eg_md.qDepth;
		}
	};

	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_queueDepth_flow) read_depth_flow = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = eg_md.qDepth; //comentar		
			result = value;
		}
	};
	
	/* save the queue time that packet passes (flow saving)*/
	Register<bit<32>, reg_index_t>(FLOWS_MONITORING) reg_Time_flow;
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_Time_flow) write_time_flow = {
		void apply(inout bit<32> value, out bit<32> result) {		
			value = eg_md.qTime;
		}
	};

	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_Time_flow) read_time_flow = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = eg_md.qTime;//comentar		
			result = value;
		}
	};

	
	//----------------------------------------------------------------------------------------

	/* save the queueID that packet passes (port saving) */
	Register<bit<32>, reg_index_t>(FLOWS_MONITORING) reg_queueID_port;
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_queueID_port) write_id_port = {
		void apply(inout bit<32> value, out bit<32> result) {			
			value = eg_md.qID;
		}
	};
	
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_queueID_port) read_id_port = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = eg_md.qID;//comentar			
			result = value;
		}
	};
	
	/* save the dequeue depth that packet passes (port saving)*/
	Register<bit<32>, reg_index_t>(FLOWS_MONITORING) reg_queueDepth_port;
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_queueDepth_port) write_depth_port = {
		void apply(inout bit<32> value, out bit<32> result) {		
			value = eg_md.qDepth;
		}
	};

	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_queueDepth_port) read_depth_port = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = eg_md.qDepth; //cmentar		
			result = value;
		}
	};
	
	/* save the queue time that packet passes (port saving)*/
	Register<bit<32>, reg_index_t>(FLOWS_MONITORING) reg_Time_port;
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_Time_port) write_time_port = {
		void apply(inout bit<32> value, out bit<32> result) {		
			value = eg_md.qTime;
		}
	};

	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_Time_port) read_time_port = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = eg_md.qTime; // comentar		
			result = value;
		}
	};

	/* save the timesmtap that packet bytes were writted (port saving)*/
	Register<bit<32>, reg_index_t>(FLOWS_MONITORING) reg_Write_Time_port;
	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_Write_Time_port) write_write_time_port = {
		void apply(inout bit<32> value, out bit<32> result) {		
			value = (bit<32>)(eg_intr_md_from_prsr.global_tstamp);
		}
	};

	RegisterAction<bit<32>, reg_index_t, bit<32>>(reg_Write_Time_port) read_write_time_port = {
		void apply(inout bit<32> value, out bit<32> result) {
			//value = eg_md.qTime;//comentar		
			result = value;
		}
	};
	//----------------------------------------------------------------------------------------

	apply {
	
	
		bit<64> l_1 = 0;

        //Tofino packet lenght has 4 bytes more than the actual packet size
		l_1 = (bit<64>)(eg_intr_md.pkt_length - 4);
			

		eg_md.qID = (bit<32>)(eg_intr_md.egress_qid);
		eg_md.qDepth = (bit<32>)(eg_intr_md.deq_qdepth);
		eg_md.qTime = (bit<32>)(eg_intr_md.enq_tstamp);
		
        //defining the flow as the hash of the destination IP. could be the 5-tuple
		flowIndex = (bit<32>)(hTableIndex.get({hdr.ipv4.dst_addr}));
        //flowIndex = (bit<32>)(hTableIndex.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr})); 
		portIndex = (bit<32>)(eg_intr_md.egress_port);

		//If is a monitoring packet, collect the information	
		if(hdr.monitor.isValid()){

			hdr.ethernet.ether_type = 0x1235;



			hdr.monitor.port = eg_intr_md.egress_port;
			hdr.monitor.pktLen = eg_intr_md.pkt_length;
			
			byte_count_port.apply(hdr.monitor.bytes_port, 0, hdr.mon_inst.index_port);
			byte_count_flow.apply(hdr.monitor.bytes_flow, 0, hdr.mon_inst.index_flow);

			//Collect queue information for the flow and the port
			hdr.monitor.qID_flow = read_id_flow.execute(hdr.mon_inst.index_flow);
			hdr.monitor.qDepth_flow = read_depth_flow.execute(hdr.mon_inst.index_flow);
			hdr.monitor.qTime_flow = read_time_flow.execute(hdr.mon_inst.index_flow);
		
			hdr.monitor.qID_port = read_id_port.execute(hdr.mon_inst.index_port);
			hdr.monitor.qDepth_port =read_depth_port.execute(hdr.mon_inst.index_port);
			hdr.monitor.qTime_port = read_time_port.execute(hdr.mon_inst.index_port);
			

			//new (just for now), collect the timestamp when the bytes of the flow were written last time
			hdr.monitor.timestamp[31:0] = read_write_time_port.execute(hdr.mon_inst.index_flow);

            //old -> was monitoring the time of the report (new is below)
			//hdr.monitor.timestamp = eg_intr_md_from_prsr.global_tstamp;

		}
		//If is not a monitoring packet, compute the information
		else{
				
			//calculate bytes per flow and per port
			
			byte_count_port.apply(dummy, l_1, portIndex);
			byte_count_flow.apply(dummy, l_1, flowIndex);			

			// save other information per flow and per port
			write_id_flow.execute(flowIndex);
			write_depth_flow.execute(flowIndex);
			write_time_flow.execute(flowIndex);
	
			write_time_port.execute(portIndex);
			write_depth_port.execute(portIndex);
			write_time_port.execute(portIndex);
	
			//new (testing)
			write_write_time_port.execute(flowIndex);		
		
		}
	}
}


control SwitchEgressDeparser(
	packet_out pkt,
	inout headers hdr,
	in my_egress_metadata_t eg_md,
	in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
		
	apply {
		pkt.emit(hdr);
	}
}



// Empty egress parser/control blocks
parser EmptyEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

control EmptyEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {}
}

control EmptyEgress(
        inout headers hdr,
	inout my_egress_metadata_t eg_md,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
	inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
		 //EmptyEgress(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;