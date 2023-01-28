import argparse
import grpc
import os
import sys
from time import sleep
import threading
from utils.switch import *
import json
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils/"))
import bmv2
#from switch import ShutdownAllSwitchConnections
from utils.convert import encodeNum, decodeNum, from_base64_to_ipv4, from_base64_to_decimal, encodeIPv4
from utils.helper import *
#import helper
from google.protobuf.json_format import MessageToDict
from geoip2 import *
import geoip2.errors
import geoip2.database

def json_read_table_entries(json_file):
    with open(json_file, 'r') as f:
        table= json.load(f)
        f.close()
    table_entries = table['table_entries']
    table_entries.pop(0)
    return table_entries

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.secure_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.secure_forward",
        action_params={
            "port": port
        })

def table_update_spoofing_on(p4info_helper, switch_connection_list):
    for switch_connection in switch_connection_list:
        json_file="table_entries_"+switch_connection.name+".json"
        table_entries=json_read_table_entries(json_file)
        for entry in table_entries:
            table_entry=p4info_helper.buildTableEntry(table_name=entry["table_name"],
            #match_fields={list(entry["match_fields"].keys())[0] : (entry["match_fields"]["hdr.ipv4.dstAddr"][0], entry["match_fields"]["hdr.ipv4.dstAddr"][1])},
            match_fields={"hdr.ipv4.dstAddr" : (entry["match_fields"]["hdr.ipv4.dstAddr"][0], entry["match_fields"]["hdr.ipv4.dstAddr"][1])},
            action_name=entry["action_name"],
            action_params={"dstAddr":entry["action_params"]["dstAddr"], "port": 255})
            switch_connection.ModifyTableEntry(table_entry)

def table_update_spoofing_off(p4info_helper, switch_connection_list):
    for switch_connection in switch_connection_list:
        json_file="table_entries_"+switch_connection.name+".json"
        table_entries=json_read_table_entries(json_file)
        for entry in table_entries:
            table_entry=p4info_helper.buildTableEntry(table_name=entry["table_name"],
            match_fields={list(entry["match_fields"].keys())[0] : (entry["match_fields"]["hdr.ipv4.dstAddr"][0], entry["match_fields"]["hdr.ipv4.dstAddr"][1])},
            action_name=entry["action_name"],
            action_params={"dstAddr":entry["action_params"]["dstAddr"], "port": entry["action_params"]["port"]})
            switch_connection.ModifyTableEntry(table_entry)

def writeIpv4Rules(p4info_helper,table, sw_id, dst_ip_addr, dst_eth_addr, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name=table,
        match_fields={"hdr.ipv4.dstAddr": (dst_ip_addr, 32)},
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": port},
    )
    sw_id.WriteTableEntry(table_entry)
    print("Installed ipv4 rule on %s" % sw_id.name)

def writeIpv4SecureRules(p4info_helper, sw_id, dst_ip_addr, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.secure_lpm",
        match_fields={"hdr.ipv4.dstAddr": (dst_ip_addr, 32)},
        action_name="MyIngress.secure_forward",
        action_params={"port": port},
    )
    sw_id.WriteTableEntry(table_entry)
    print("Installed ipv4 secure rule on %s" % sw_id.name)


def writeFirewallRules(p4info_helper, ingress_sw, geoname_id):
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.firewall_exact",
            match_fields={
                "hdr.gss.geoname_id": geoname_id
            },
            action_name="MyIngress.drop",
            action_params={
            })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed ifirewall rule on %s" % ingress_sw.name)


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print("\n----- Reading tables rules for %s -----" % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            print(entry)

def check_spoofing(ipv4_address, geoname_id):
    result=False
    try:
        reader=geoip2.database.Reader("/home/p4/Desktop/Originale/GeoLite2-City_20221004/GeoLite2-City.mmdb")
        response=reader.city(ipv4_address)
        real_geoname_id=response.city.geoname_id
        #print(response.city.name)
        #print(response.city.geoname_id)
        if geoname_id == real_geoname_id:
            result=True
    except geoip2.errors.AddressNotFoundError:
        print("Address not present in the database")
    reader.close()
    return result

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.
    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))
            return counter.data.byte_count



def printGrpcError(e):
    print("gRPC Error:", e.details(), end="")
    status_code = e.code()
    print("(%s)" % status_code.name, end="")
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


def thread1(p4info_helper, switch_connection):
    while True:
        packetin = switch_connection.PacketIn()# Packet in!
        if packetin is not None:
            print("PACKET IN received")
            #print(packetin)
            packet = packetin.packet.payload
            d = MessageToDict(packetin.packet)
            geoname_id=from_base64_to_decimal(d['metadata'][0]['value'])
            srcAddr=from_base64_to_ipv4(d['metadata'][1]['value'])
            print("Geoname_ID: %d\nsrcAddr: %s" % (geoname_id,srcAddr))
            print("Spoofing check result: %s" %(check_spoofing(srcAddr, geoname_id)))
            print(switch_connection.name)
            if check_spoofing(srcAddr, geoname_id):
                packetout = p4info_helper.buildPacketOut(
                    payload=packet,
                    metadata={
                        1: encodeNum(1, 16) #the reason_id assumes always the value 1, useful in future for new features
                    },
                )
                print("send PACKET OUT")
                switch_connection.PacketOut(packetout)


def thread2(p4info_helper, switch_connection_list):
    check_spoofing=0
    print("The spoofing check is currently disabled!\n")
    num=int(input("If you want to enable spoofing check, please answer 1: \n"))
    s1=switch_connection_list[0]
    s2=switch_connection_list[1]
    s3=switch_connection_list[2]
    s4=switch_connection_list[3]
    while True:
         if num == 1:
             table_update_spoofing_on(p4info_helper, switch_connection_list)
             print("The spoofing check is currently enabled!\n")
             sleep(10)
             num=int(input("If you want to disable spoofing check, please answer 0: \n"))

         elif num == 0:
             table_update_spoofing_off(p4info_helper, switch_connection_list)
             print("The spoofing check is currently disabled!\n")
             sleep(10)
             num=int(input("If you want to enable spoofing check answer 1: \n"))
         check_spoofing=num

def thread3(p4info_helper, switch_connection_list):
    s4=switch_connection_list[3]
    old_counter=0
    new_counter=printCounter(p4info_helper, s4, "c", 0)
    data_rate=(new_counter-old_counter)/5000
    localtime=time.localtime()
    result=time.strftime("%I:%M:%S_%p", localtime)
    data_rate="bit_rate: %s KBps" % (data_rate)
    print(result, data_rate)
    sleep(5)
    while True:
        old_counter=new_counter
        trashold=1000 #1 MBps
        new_counter=printCounter(p4info_helper, s4,  "c", 0)
        data_rate=(new_counter-old_counter)/5000
        if data_rate > trashold:
            print("DDoS detected")
        else:
            print("Normal traffic")
        localtime=time.localtime()
        result=time.strftime("%I:%M:%S_%p", localtime)
        data_rate="bit_rate: %s KBps" % (data_rate)

        print(result, data_rate)
        print("Press 1 if you want to enable the spoofing check, 0 if you want to disable it, or nothing to continue in this way: ")
        sleep(5)


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = P4InfoHelper(p4info_file_path)
    try:
        # Create a switch connection object for s1, s2, s3 and s4;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = bmv2.Bmv2SwitchConnection(
            name="s1",
            address="0.0.0.0:50051",
            device_id=1,
            proto_dump_file="p4runtime1.log",
        )
        s2 = bmv2.Bmv2SwitchConnection(
            name="s2",
            address="0.0.0.0:50052",
            device_id=2,
            proto_dump_file="p4runtime2.log",
        )
        s3 = bmv2.Bmv2SwitchConnection(
            name="s3",
            address="0.0.0.0:50053",
            device_id=3,
            proto_dump_file="p4runtime3.log",
        )
        s4 = bmv2.Bmv2SwitchConnection(
            name="s4",
            address="0.0.0.0:50054",
            device_id=4,
            proto_dump_file="p4runtime4.log",
        )
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        if s1.MasterArbitrationUpdate() == None:
            print("Failed to establish the connection")
        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path
        )
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")

        if s2.MasterArbitrationUpdate() == None:
            print("Failed to establish the connection")
        s2.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path
        )
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")

        if s3.MasterArbitrationUpdate() == None:
            print("Failed to establish the connection")
        s3.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path
        )
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        if s4.MasterArbitrationUpdate() == None:
            print("Failed to establish the connection")
        s4.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path
        )
        print("Installed P4 Program using SetForwardingPipelineConfig on s4")

        #S1
        writeIpv4Rules(p4info_helper,  sw_id=s1, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="8.27.67.188", dst_eth_addr= "08:00:00:00:01:11",port=1)
        writeIpv4Rules(p4info_helper, sw_id=s1, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="31.28.27.50", dst_eth_addr= "08:00:00:00:00:02",port=10)
        writeIpv4Rules(p4info_helper,  sw_id=s1, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="89.46.106.33", dst_eth_addr= "08:00:00:00:00:02",port=10)
        writeIpv4Rules(p4info_helper, sw_id=s1, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="95.110.235.107", dst_eth_addr= "08:00:00:00:00:04",port=11)
        writeIpv4Rules(p4info_helper,  sw_id=s1, table="MyIngress.ipv4_lpm", dst_ip_addr="8.27.67.188", dst_eth_addr= "08:00:00:00:01:11",port=1)
        writeIpv4Rules(p4info_helper, sw_id=s1, table="MyIngress.ipv4_lpm", dst_ip_addr="31.28.27.50", dst_eth_addr= "08:00:00:00:00:02",port=10)
        writeIpv4Rules(p4info_helper, sw_id=s1, table="MyIngress.ipv4_lpm", dst_ip_addr="89.46.106.33", dst_eth_addr= "08:00:00:00:00:02",port=10)
        writeIpv4Rules(p4info_helper, sw_id=s1, table="MyIngress.ipv4_lpm", dst_ip_addr="95.110.235.107", dst_eth_addr= "08:00:00:00:00:04",port=11)
        writeIpv4SecureRules(p4info_helper,  sw_id=s1, dst_ip_addr="8.27.67.188", port=1)
        writeIpv4SecureRules(p4info_helper,  sw_id=s1, dst_ip_addr="31.28.27.50", port=10)
        writeIpv4SecureRules(p4info_helper,  sw_id=s1, dst_ip_addr="89.46.106.33", port=10)
        writeIpv4SecureRules(p4info_helper,  sw_id=s1, dst_ip_addr="95.110.235.107", port=11)

        #S2
        writeIpv4Rules(p4info_helper,  sw_id=s2, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="31.28.27.50", dst_eth_addr= "08:00:00:00:01:22",port=1)
        writeIpv4Rules(p4info_helper, sw_id=s2, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="8.27.67.188", dst_eth_addr= "08:00:00:00:00:01",port=10)
        writeIpv4Rules(p4info_helper, sw_id=s2, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="89.46.106.33", dst_eth_addr= "08:00:00:00:00:03",port=11)
        writeIpv4Rules(p4info_helper, sw_id=s2, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="95.110.235.107", dst_eth_addr= "08:00:00:00:00:03",port=11)
        writeIpv4Rules(p4info_helper,  sw_id=s2, table="MyIngress.ipv4_lpm", dst_ip_addr="31.28.27.50", dst_eth_addr= "08:00:00:00:01:22",port=1)
        writeIpv4Rules(p4info_helper, sw_id=s2, table="MyIngress.ipv4_lpm", dst_ip_addr="8.27.67.188", dst_eth_addr= "08:00:00:00:00:01",port=10)
        writeIpv4Rules(p4info_helper, sw_id=s2, table="MyIngress.ipv4_lpm", dst_ip_addr="89.46.106.33", dst_eth_addr= "08:00:00:00:00:03",port=11)
        writeIpv4Rules(p4info_helper, sw_id=s2, table="MyIngress.ipv4_lpm", dst_ip_addr="95.110.235.107", dst_eth_addr= "08:00:00:00:00:03",port=11)
        writeIpv4SecureRules(p4info_helper,  sw_id=s2, dst_ip_addr="8.27.67.188", port=10)
        writeIpv4SecureRules(p4info_helper,  sw_id=s2, dst_ip_addr="31.28.27.50", port=1)
        writeIpv4SecureRules(p4info_helper,  sw_id=s2, dst_ip_addr="89.46.106.33", port=11)
        writeIpv4SecureRules(p4info_helper,  sw_id=s2, dst_ip_addr="95.110.235.107", port=11)

        #S3
        writeIpv4Rules(p4info_helper,  sw_id=s3, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="89.46.106.33", dst_eth_addr= "08:00:00:00:01:33",port=1)
        writeIpv4Rules(p4info_helper, sw_id=s3, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="31.28.27.50", dst_eth_addr= "08:00:00:00:00:02",port=11)
        writeIpv4Rules(p4info_helper, sw_id=s3, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="8.27.67.188", dst_eth_addr= "08:00:00:00:00:02",port=11)
        writeIpv4Rules(p4info_helper, sw_id=s3, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="95.110.235.107", dst_eth_addr= "08:00:00:00:00:04",port=10)
        writeIpv4Rules(p4info_helper,  sw_id=s3, table="MyIngress.ipv4_lpm", dst_ip_addr="89.46.106.33", dst_eth_addr= "08:00:00:00:01:33",port=1)
        writeIpv4Rules(p4info_helper, sw_id=s3, table="MyIngress.ipv4_lpm", dst_ip_addr="31.28.27.50", dst_eth_addr= "08:00:00:00:00:02",port=11)
        writeIpv4Rules(p4info_helper, sw_id=s3, table="MyIngress.ipv4_lpm", dst_ip_addr="8.27.67.188", dst_eth_addr= "08:00:00:00:00:02",port=11)
        writeIpv4Rules(p4info_helper, sw_id=s3, table="MyIngress.ipv4_lpm", dst_ip_addr="95.110.235.107", dst_eth_addr= "08:00:00:00:00:04",port=10)
        writeIpv4SecureRules(p4info_helper,  sw_id=s3, dst_ip_addr="89.46.106.33", port=1)
        writeIpv4SecureRules(p4info_helper,  sw_id=s3, dst_ip_addr="8.27.67.188", port=11)
        writeIpv4SecureRules(p4info_helper,  sw_id=s3, dst_ip_addr="31.28.27.50", port=11)
        writeIpv4SecureRules(p4info_helper,  sw_id=s3, dst_ip_addr="95.110.235.107", port=10)

        #S4
        writeIpv4Rules(p4info_helper,  sw_id=s4, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="95.110.235.107", dst_eth_addr= "08:00:00:00:01:44",port=1)
        writeIpv4Rules(p4info_helper, sw_id=s4, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="8.27.67.188", dst_eth_addr= "08:00:00:00:00:01",port=11)
        writeIpv4Rules(p4info_helper, sw_id=s4, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="31.28.27.50", dst_eth_addr= "08:00:00:00:00:03",port=10)
        writeIpv4Rules(p4info_helper, sw_id=s4, table="MyIngress.ipv4_lpm_for_ssh", dst_ip_addr="89.46.106.33", dst_eth_addr= "08:00:00:00:00:03",port=10)
        writeIpv4Rules(p4info_helper,  sw_id=s4, table="MyIngress.ipv4_lpm", dst_ip_addr="95.110.235.107", dst_eth_addr= "08:00:00:00:01:44",port=1)
        writeIpv4Rules(p4info_helper, sw_id=s4, table="MyIngress.ipv4_lpm", dst_ip_addr="8.27.67.188", dst_eth_addr= "08:00:00:00:00:01",port=11)
        writeIpv4Rules(p4info_helper, sw_id=s4, table="MyIngress.ipv4_lpm", dst_ip_addr="31.28.27.50", dst_eth_addr= "08:00:00:00:00:03",port=10)
        writeIpv4Rules(p4info_helper, sw_id=s4, table="MyIngress.ipv4_lpm", dst_ip_addr="89.46.106.33", dst_eth_addr= "08:00:00:00:00:03",port=10)
        writeIpv4SecureRules(p4info_helper,  sw_id=s4, dst_ip_addr="95.110.235.107", port=1)
        writeIpv4SecureRules(p4info_helper,  sw_id=s4, dst_ip_addr="8.27.67.188", port=11)
        writeIpv4SecureRules(p4info_helper,  sw_id=s4, dst_ip_addr="31.28.27.50", port=10)
        writeIpv4SecureRules(p4info_helper,  sw_id=s4, dst_ip_addr="89.46.106.33", port=10)



        writeFirewallRules(p4info_helper, s1, 498817) #San Pietroburgo
        writeFirewallRules(p4info_helper, s1,1796236) #Shangai
        writeFirewallRules(p4info_helper, s2, 498817) #San Pietroburgo
        writeFirewallRules(p4info_helper, s2,1796236) #Shangai
        writeFirewallRules(p4info_helper, s3, 498817) #San Pietroburgo
        writeFirewallRules(p4info_helper, s3,1796236) #Shangai
        printCounter(p4info_helper, s4, "c", 0)

        # read all table rules
        #readTableRules(p4info_helper, s1)
        lista=[s1, s2, s3, s4]
        t_s1 = threading.Thread(target=thread1, args=(p4info_helper, s1))
        t_s2 = threading.Thread(target=thread1, args=(p4info_helper, s2))
        t_s3 = threading.Thread(target=thread1, args=(p4info_helper, s3))
        t_s4 = threading.Thread(target=thread1, args=(p4info_helper, s4))
        t2 = threading.Thread(target=thread2, args=(p4info_helper, lista))
        t3 = threading.Thread(target=thread3, args=(p4info_helper, lista))


        # starting threads
        t_s1.start()
        t_s2.start()
        t_s3.start()
        t_s4.start()
        t2.start()
        t3.start()

        t_s1.join()
        t_s2.join()
        t_s3.join()
        t_s4.join()
        t2.join()
        t3.join()

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)
    ShutdownAllSwitchConnections()
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="P4Runtime Controller")
    parser.add_argument(
        "--p4info",
        help="p4info proto in text format from p4c",
        type=str,
        action="store",
        required=False,
        default="./switch_config.p4info.txt",
    )
    parser.add_argument(
        "--bmv2-json",
        help="BMv2 JSON file from p4c",
        type=str,
        action="store",
        required=False,
        default="./switch_config.json",
    )
    args = parser.parse_args()
    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file %s not found!" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file %s not found!" % args.bmv2_json)
        parser.exit(2)
    main(args.p4info, args.bmv2_json)
