#!/usr/bin/env python3

import ssl, os, json, yaml, requests, argparse, logging, pprint

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

    #Log Search
    searchdata = {
        "id": 2,
        "jsonrpc": "2.0",
        "method": "add",
        "params": [
            {
                "apiver": 3,
                "logtype": "traffic",
                "time-order": "desc",
                "time-range": {
                    "end": "2022-04-05T13:00:00",
                    "start": "2022-04-05T08:10:00",
                },
                "url": "/logview/adom/root/logsearch",
            }
        ],
        "session": sessionkey
        } 

    searchreq = requests.post(url, data=json.dumps(searchdata), headers=headers)
    searchdatajson = searchreq.json()
    task = searchdatajson['result']['tid']
    print(task)

    #Log Search get task ID
    taskid = {
        "id": 3,
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
            "apiver": 3,
            "limit": 50,
            "offset": 0,
            "url": "/logview/adom/root/logsearch/%s" % task
            }
        ],
        "session": sessionkey
        }

    taskidreq = requests.post(url, data=json.dumps(taskid), headers=headers)
    taskidjson = taskidreq.json()
    pprint.pprint(taskidjson)


    #Logout of FAZ
    try:
        authlogout = {
            "method": "exec",
            "params": [
                {
                "url": "/sys/logout"
                }
            ],
            "session": sessionkey,
            "id": 4
            } 

        requests.post(url, data=json.dumps(authlogout), headers=headers)
    except:
        logging.error('Unable to logout of FortiAnalyzer')



if __name__ == '__main__':
    main()