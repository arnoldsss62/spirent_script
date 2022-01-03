import pyshark
import json
import time
import sys
from function import connection_general 
import re

test_name=sys.argv[1]
test_path= sys.argv[2]

id,get_response,file_path = connection_general(test_name,test_path)
file_path=test_path

if test_name=="MME_NODAL_1-OMEC":
    json_data_out={}
    EMM=get_response.json()["tabs"]["EMM"]
    ESM =get_response.json()["tabs"]["ESM"]
    SCTP =get_response.json()["tabs"]["SCTP"]
    enodeB= get_response.json()["tabs"]["eNodeB User Node"]
    json_data_out["SCTP Link"]= True if int(SCTP["Socket Connect Count"]) == 1 else False
    json_data_out["S1 Setup"]=True if float(get_response.json()["tabs"]["S1-AP"]["Setup Responses Received"])/float(get_response.json()["tabs"]["S1-AP"]["Setup Requests Sent"]) >=0.99 else False
    json_data_out["UE EPC attachment"]=True if float(EMM["Attach Accepts"])/float(EMM["Attach Requests"]) >=0.98 else False
    json_data_out["UE initiated EPC detachment"]=True if EMM["Detach Requests"] == EMM["Detach Responses"]  else False
    json_data_out["Successful EPS Attach with IMSI"]=True if float(EMM["Attach Accepts"])/float(EMM["Attach Requests"]) >=0.99 and float(EMM["Auth Responses"])/float(EMM["Auth Requests"]) >=0.99 and float(EMM["Security Mode Completes"])/float(EMM["Security Mode"]) >= 0.99 and float(ESM["Activate Context Accepts"])/float(ESM["Activate Context Requests"]) >= 0.99 else False
    json_data_out["GTP-U echo mechanism"]= True if float(enodeB["Echo Requests Sent"])/float(enodeB["Echo Responses Received"]) >=0.99 else False

    ##PCAP processing
    name=test_name
    pcap_file='test_%s.pcap' %name

    cap=pyshark.FileCapture('%s/%s' %(file_path,pcap_file),display_filter='s1ap')
    records=[]
    for packet in cap:
        if 'Attach request' in str(packet) and 'Type of identity: IMSI' in str(packet):
            print("valid packet")
            records.append(packet)
        if 'Attach complete' in str(packet) and 'NAS EPS Mobility Management Message Type: Attach complete' in str(packet) :
            print("valid packet")
            records.append(packet)
    cap.close()
    json_data_out["Successful EPS Attach with IMSI"]=True if len(records)>=2  and json_data_out["Successful EPS Attach with IMSI"] else False
    #json_data_out["pcap"]= True if not not records else False
            
    json_data_out["id"]=id
    print(json_data_out)

elif test_name=="MME_NODAL_2-OMEC":
    json_data_out={}
    EMM=get_response.json()["tabs"]["EMM"]
    ESM =get_response.json()["tabs"]["ESM"]
    SCTP =get_response.json()["tabs"]["SCTP"]

    json_data_out["Successful EPS Attach with UE known in MME and Ciphering"]=True if float(EMM["Attach Accepts"])/float(EMM["Attach Requests"]) >=0.99 and float(EMM["Auth Responses"])/float(EMM["Auth Requests"]) >=0.99 and float(EMM["Security Mode Completes"])/float(EMM["Security Mode"]) >= 0.99 and float(ESM["Activate Context Accepts"])/float(ESM["Activate Context Requests"]) >= 0.99 else False

    ##PCAP processing
    pcap_file='test_%s.pcap' %test_name

    cap=pyshark.FileCapture('%s/%s' %(file_path,pcap_file),display_filter='s1ap')
    records=[]
    for packet in cap:
        if 'Attach request' in str(packet) and 'Type of identity: GUTI' in str(packet):
            print("valid packet")
            records.append(packet)
        if 'Attach complete' in str(packet) and 'NAS EPS Mobility Management Message Type: Attach complete' in str(packet) :
            print("valid packet")
            records.append(packet)
    cap.close()
    json_data_out["Successful EPS Attach with UE known in MME and Ciphering"]= True if len(records)>=2  and json_data_out["Successful EPS Attach with UE known in MME and Ciphering"] else False 
    json_data_out["id"]=id
    print(json_data_out)


elif test_name=="MME_NODAL_3-OMEC":

    json_data_out={}
    ##Data thoughput test

    speed=get_response.json()["tabs"]["External Apps|SpeedTest Lab"]
    json_data_out["Data throughput test"]=True if float(speed["Speed Test Lab Down Speed (Mbps)"].replace(",","")) > 0 and float(speed["Speed Test Lab Up Speed (Mbps)"].replace(",","")) > 0 else False
    json_data_out["id"]=id
    print(json_data_out)   

elif test_name=="MME_NODAL_4-OMEC":

    json_data_out={}
    EMM=get_response.json()["tabs"]["EMM"]
    ESM =get_response.json()["tabs"]["ESM"]
    SCTP =get_response.json()["tabs"]["SCTP"]

    json_data_out["Unsuccessful EPS Attach due to IMSI unknown to HSS"]=True if float(EMM["MSID Cannot Be Derived By Ntwk"]) == float(EMM["Attach Rejects"])  else False
    json_data_out["id"]=id
    print(json_data_out)


elif test_name=="MME_NODAL_5-OMEC":

    json_data_out={}
    EMM=get_response.json()["tabs"]["EMM"]
    ESM =get_response.json()["tabs"]["ESM"]
    SCTP =get_response.json()["tabs"]["SCTP"]

    json_data_out["Successful EPS Detach initiated by UE"]= True if float(EMM["Detach Requests Sent"]) == float(EMM["Detach Responses Received"])  else False

    ##PCAP processing
    pcap_file='test_%s.pcap' %test_name

    cap=pyshark.FileCapture('%s/%s' %(file_path,pcap_file),display_filter='s1ap')
    records=[]
    for packet in cap:
        if 'Detach request' in str(packet) and 'Switch off: Normal detach' in str(packet):
            print("valid packet")
            records.append(packet)
        if 'Detach accept' in str(packet) and 'NAS EPS Mobility Management Message Type: Dettach accept' in str(packet):
            print("valid packet")
            records.append(packet)
    cap.close()

    json_data_out["Successful EPS Detach initiated by UE"]= True if len(records)>=2 and json_data_out["Successful EPS Detach initiated by UE"] else False

    json_data_out["id"]=id
    print(json_data_out)

elif test_name=="MME_NODAL_6-OMEC":

    json_data_out={}    
    EMM=get_response.json()["tabs"]["EMM"]
    ESM =get_response.json()["tabs"]["ESM"]

    json_data_out["Successful EPS Detach initiated by UE due to switch off"]=True if float(EMM["Detach Requests Sent"]) == float(EMM["Detach Responses Received"])  else False

    ##PCAP processing
    pcap_file='test_%s.pcap' %test_name

    cap=pyshark.FileCapture('%s/%s' %(file_path,pcap_file),display_filter='s1ap')
    records=[]
    for packet in cap:
        if 'Detach request' in str(packet) and 'Switch off: Switch off' in str(packet):
            print("valid packet")
            records.append(packet)
        if 'Detach accept' in str(packet) and 'NAS EPS Mobility Management Message Type: Dettach accept' in str(packet):
            print("valid packet")
            records.append(packet)
    cap.close()
    json_data_out["Successful EPS Detach initiated by UE due to switch off"]= True if len(records)>=2 and json_data_out["Successful EPS Detach initiated by UE due to switch off"] else False

    json_data_out["id"]=id
    print(json_data_out)

elif test_name=="MME_NODAL_7-OMEC":


    json_data_out={}
    EMM=get_response.json()["tabs"]["EMM"]
    ESM =get_response.json()["tabs"]["ESM"]
    SCTP =get_response.json()["tabs"]["SCTP"]
    #json_data_out["SCTP Link"]= True if SCTP["Socket Connect Count"] == SCTP
    json_data_out["Periodic TAU"]=True if float(EMM["TAU Accepts"])/float(EMM["TAU Requests"]) >=0.99 else False
    json_data_out["id"]=id
    print(json_data_out)


elif test_name=="MME_NODAL_8-OMEC":

    json_data_out={}
    S1=get_response.json()["tabs"]["S1-AP"]
    ESM =get_response.json()["tabs"]["ESM"]
    SCTP =get_response.json()["tabs"]["SCTP"]

    json_data_out["Inter-eNB handover (same MME)"]=True if float(S1["Path Switch Request Acks"])/float(S1["Path Switch Requests"]) >=0.99 else False

    print(json_data_out)

elif test_name=="MME_NODAL_10-OMEC":

    json_data_out={}
    EMM=get_response.json()["tabs"]["EMM"]
    S1=get_response.json()["tabs"]["S1-AP"]
    ESM =get_response.json()["tabs"]["ESM"]
    SCTP =get_response.json()["tabs"]["SCTP"]

    json_data_out["UE/eNB Context Release due to User Inactivity with a single bearer established"]=True if float(S1["S1 Release Completes"])/float(S1["S1 Release Requests"]) >=0.99 else False
    json_data_out["Successful Service Request invoked when the UE has uplink signaling pending in ECM-Idle mode (Single Bearer)"]=True if float(EMM["Service Requests - UE Triggered"])/float(EMM["Service Accepts - UE Triggered"]) >=0.99 else False
    json_data_out["id"]=id
    print(json_data_out)

elif test_name=="MME_NODAL_5GNSA_3x":
    print("For NSA")

    json_data_out={}
    EMM=get_response.json()["tabs"]["EMM"]
    ESM =get_response.json()["tabs"]["ESM"]
    SCTP =get_response.json()["tabs"]["SCTP"]
    json_data_out["5G-NSA Dual Connectivity Attach"]=True if float(EMM["Attach Accepts"])/float(EMM["Attach Requests"]) >=0.99 and float(EMM["Auth Responses"])/float(EMM["Auth Requests"]) >=0.99 and float(EMM["Security Mode Completes"])/float(EMM["Security Mode"]) >= 0.99 and float(ESM["Activate Context Accepts"])/float(ESM["Activate Context Requests"]) >= 0.99 else False
    #json_data_out["GTP-U echo mechanism"]= True  ##Consultar con Luis 

    ##PCAP processing
    name=test_name
    pcap_file='test_%s.pcap' %test_name

    cap=pyshark.FileCapture('%s/%s' %(file_path,pcap_file),display_filter='s1ap')
    records=[[],[],[],[]]
    validation=False
    id_confirm=0
    id_ind=0
    for packet in cap:
        if 'Attach request' in str(packet) and 'Dual connectivity with NR: Supported' in str(packet) and 'UE additional security capability' in str(packet):
            print("valid packet")
            records[0].append(packet)
        if 'Attach complete' in str(packet) and 'NAS EPS Mobility Management Message Type: Attach complete' in str(packet) :
            print("valid packet")
            records[1].append(packet)
        if 'E-RABConfirmationIndication' in str(packet)  :
            print("valid packet")
            records[2].append(packet)
            match=re.search(r'e-RAB-ID: ([\d])',str(packet))
            id_ind=match.group(1)

        if 'E-RABConfirmationConfirm' in str(packet)  :
            print("valid packet")
            records[3].append(packet)
            match=re.search(r'e-RAB-ID: ([\d])',str(packet))
            id_confirm=match.group(1)
        
        
    cap.close()
    json_data_out["5G-NSA Dual Connectivity Attach"]=True if len(records)>=2  and json_data_out["5G-NSA Dual Connectivity Attach"] else False
    #json_data_out["pcap"]= True if not not records else False
    json_data_out["5G-NSA Dual connectivity 3x option"] = True if len(records[0])==len(records[1]) and len(records[2])==len(records[3]) and id_ind==id_confirm else False
    json_data_out["5G NSA Dual Connectivity Service Request procedure"] =True if float(EMM["Service Requests - UE Triggered"])/float(EMM["Service Accepts - UE Triggered"]) >=0.99 else False
    json_data_out["id"]=id
    print(json_data_out)

else :
    print("others")
