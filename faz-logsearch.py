#!/usr/bin/env python3

import ssl, json, requests, argparse, logging, csv

ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings() 

def main():
    ################ MODIFY THESE VARIABLES #############################################################################
    startdatetime = '2022-04-04T08:01:00'              # Enter the start date and time in this format YYYY-MM-DDTHH:MM:SS
    enddatetime = '2022-04-05T16:01:00'                # Enter the end date and time in this format YYYY-MM-DDTHH:MM:SS
    adom = 'root'                                      # FortiAnalyzer ADOM
    filter1 = 'srcip=10.100.92.16'                     # Filter variable such as source IP address Filter (Leave blank for all)
    filter2 = 'dstip=8.8.8.8'                          # Filter variable such as destination IP address Filter (Leave blank for all)
    lines = '20'                                       # How many lines to return
    #####################################################################################################################

    # Arg Parser to add arguments at runtime (./faz-logsearch.py --fortianalyzer 192.168.101.10 --user test --password changeme)
    parser = argparse.ArgumentParser()
    parser.add_argument('--fortianalyzer', default='', help='FortiAnalyzer IP Address')
    parser.add_argument('--user', default='', help='FAZ API User')
    parser.add_argument('--password', default='', help='FAZ API User Password')
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
            "filter": "%s" % filter1,
            "filter": "%s" % filter2,
            "time-order": "desc",
            "time-range": {
                "end": "%s" % enddatetime,
                "start": "%s" % startdatetime,
            },
            "url": "/logview/adom/%s/logsearch" % adom,
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
            "limit": '%s' % lines,
            "offset": 0,
            "url": "/logview/adom/%s/logsearch/%s" % (adom, task)
            }
        ],
        "session": "%s" % sessionkey
        }

    taskidreq = requests.post(url, data=json.dumps(taskid), headers=headers)
    taskidjson = taskidreq.json()

    while taskidjson['result']['percentage'] < 100:
        taskidreq = requests.post(url, data=json.dumps(taskid), headers=headers)
        taskidjson = taskidreq.json()
    
    #Write logs to csv file
    data_file = open('data_file.csv', 'w')
    csv_writer = csv.writer(data_file)
    count = 0
    for log in taskidjson['result']['data']:
        if count == 0:
            header = log.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(log.values())
    data_file.close()

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