#!/usr/bin/env python3

from multiprocessing.connection import wait
import ssl, os, json, sys, requests, argparse, logging, pprint
from time import sleep

ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings() 

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fortianalyzer', default='jmahaffey-api-test.fortidemo.fortinet.com:10405', help='Firewall IP Address')
    parser.add_argument('--user', default='', help='FAZ API User')
    parser.add_argument('--password', default='', help='FAZ API User Password')
    parser.add_argument('--logging', default='', help='Logging levels info, error, or debug')
    parser.add_argument('--devlist', default='address.csv', help='YAML/CSV file with list of approved devices.')
    args = parser.parse_args()

    url = 'https://%s/jsonrpc' % args.fortianalyzer
    headers = {'content-type': "application/json"}

    #Login to FAZ and get session key
    authlogin = {
        "method": "exec",
        "params": [
            {
            "data": {
                "passwd": args.password,
                "user": args.user
            },
            "url": "/sys/login/user"
            }
        ],
        "id": 1
        }

    try:
        token = requests.post(url, data=json.dumps(authlogin), headers=headers)
        tokenjson = token.json()
        sessionkey = tokenjson['session']
    except:
        logging.error('Unable to login to FortiAnalyzer')
        exit()

    #Log Search - Modify the filter key and time ranges
    searchdata = {
        "id": 2,
        "jsonrpc": "2.0",
        "method": "add",
        "params": [
            {
                "device": [
                    {
                        "devid": "All_FortiGate"
                    }
                ],
                "apiver": 3,
                "logtype": "traffic",
                "filter": "srcip=10.100.92.16",
                "filter": "dstip=8.8.8.8",
                "time-order": "desc",
                "time-range": {
                    "end": "2022-04-05T15:58:00",
                    "start": "2022-04-04T13:01:00",
                },
                "url": "/logview/adom/root/logsearch",
            }
        ],
        "session": "%s" % sessionkey
        } 

    searchreq = requests.post(url, data=json.dumps(searchdata), headers=headers)
    searchdatajson = searchreq.json()
    task = searchdatajson['result']['tid']

    #Log Search get task ID
    taskid = {
        "id": 3,
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
            "apiver": 3,
            "limit": 10,
            "offset": 0,
            "url": "/logview/adom/root/logsearch/%s" % task
            }
        ],
        "session": "%s" % sessionkey
        }

    taskidreq = requests.post(url, data=json.dumps(taskid), headers=headers)
    taskidjson = taskidreq.json()

    while taskidjson['result']['percentage'] < 100:
        taskidreq = requests.post(url, data=json.dumps(taskid), headers=headers)
        taskidjson = taskidreq.json()
    
    with open('search_output.json', 'w') as search:
        json.dump(taskidjson['result']['data'], search)


    #Logout of FAZ
    try:
        authlogout = {
            "method": "exec",
            "params": [
                {
                "url": "/sys/logout"
                }
            ],
            "session": "%s" % sessionkey,
            "id": 4
            } 

        requests.post(url, data=json.dumps(authlogout), headers=headers)
    except:
        logging.error('Unable to logout of FortiAnalyzer')



if __name__ == '__main__':
    main()