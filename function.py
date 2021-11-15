import requests
from requests.auth import HTTPBasicAuth
import pyshark
import json
import time
import os
def connection_general(test_name):

    endpoint="http://10.95.208.85:8080/api/"
    end_running="http://10.95.208.85:8080/api/runningTests/"
    auth_data=HTTPBasicAuth('sms', 'a1b2c3d4')

    name=test_name

    data={
    "library": 342,
    "name": name
    }

    json_data = json.dumps(data) 

    #Start test session with name in the proper library
    post_response = requests.post(end_running, auth=auth_data , data=json_data)

    id=post_response.json()["id"] #Get ID of test, used below
    print("ID : %s" %id)

    test_end=post_response.json()["url"]
    #time.sleep(60)

    get_response = requests.get(test_end, auth=auth_data )

    while  True :
        if "resultFilesList"  in get_response.json().keys():
            if len(get_response.json()["resultFilesList"])>=2:
                #print (get_response.json()["resultFilesList"])
                break
            else:
                time.sleep(10)
                print("Esperando que test se realice")
                get_response = requests.get(test_end, auth=auth_data )
        else:
                time.sleep(10)
                print("Esperando que test se realice")
                #print(get_response.json().keys())
                get_response = requests.get(test_end, auth=auth_data )   


    end_2 = get_response.json()["resultFilesList"]

    file_path=download_file(end_2,test_name)

    test_measurmnt=get_response.json()["measurementsUrl"]
    #print(test_measurmnt)
    get_response = requests.get(test_measurmnt, auth=auth_data )

    close_connection(test_end)

    return id,get_response,file_path

def close_connection(test_end):
    #STOP test session
    auth_data=HTTPBasicAuth('sms', 'a1b2c3d4')
    post_response = requests.post(test_end+'?action=stop', auth=auth_data )
    time.sleep(5)
    del_response=requests.delete(test_end,auth=auth_data)

def download_file(end_2,name):

    auth_data=HTTPBasicAuth('sms', 'a1b2c3d4')

    #####COMPLETE SPECIFIC PATH OF XLS AND PCAP FILES
    file_path="/home/arnold/trabajo/spirent_script"

    receive = requests.get(end_2[1], auth=auth_data ) # First (0) for log and (1) for xls file
    with open('%s/test_%s.xls' %(file_path,name),'wb') as f:
        f.write(receive.content)

    if len(end_2)==3:
        receive = requests.get(end_2[2], auth=auth_data ) # First (0) for log and (1) for xls file
        with open('%s/test_%s.pcap' %(file_path,name),'wb') as f:
            f.write(receive.content)

    return file_path
