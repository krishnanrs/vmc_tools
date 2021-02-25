# VMC Tools

This contains a collection of python based scripts for troubleshooting VMWare Cloud on AWS issues.
**Note**: The script require you to set the value of the `VMC_REFRESH_TOKEN` variable to your VMC Operator refresh token for authentication.

## instance_boot_time

This script reports the host uptime by invoking a backend RTS script. To get the uptime of a specific host, you can provide an optional hostname (for e.g. esx-0) or IP address. Otherwise is queries and reports the uptime of all hosts in the SDDC.
```
usage: instance_boot_time.py -S SDDC_ID [-I IP_ADDRESS] [-n HOST_NAME] [-h]

optional arguments:
  -S SDDC_ID, --sddc-id SDDC_ID
                        SDDC ID of the affected instance
  -I IP_ADDRESS, --ip-address IP_ADDRESS
                        IP Address of instance
  -n HOST_NAME, --host-name HOST_NAME
                        Host name of instance
  -h, --help
  ```

**Example**:
```
$ ./instance_boot_time.py -S bd2ce819-d7dc-4860-8179-a9e4fb27b83e 
('Host', 'instanceId', 'uptime (Days)')
(u'esx-0', u'i-082fd01b75da30dc4', 51)
(u'esx-1', u'i-0137d7b2b6af485fc', 51)
(u'esx-2', u'i-06ec68d4ae7e943ac', 51)
```

**Note**: This script requires intranet (VPN) access as RTS service is only available on the intranet

## instance_failure

This script does the following:

 - Queries the instance information like state, instance type, launch time etc., from AWS
 - Extracts the console logs of the instance (if available)
 - Parsers the console logs for known hardware failure signature(s)
 - Queries the cloudwatch metrics for the instance (by default for the past 3 hours)
 - Outputs a recommendation (whether to file a PR or an AWS ticket) based on this data
 - Additionally the script also provides an option to query autoscaler tasks for the instance
 - Also provides an option to query the host state from the vCenter using a RTS script, which helps identify if the host got rebooted

```
  -S SDDC_ID, --sddc-id SDDC_ID
                        SDDC ID of the affected instance
  -I IP_ADDRESS, --ip-address IP_ADDRESS
                        IP Address of affected instance
  -i INSTANCE_ID, --instance-id INSTANCE_ID
                        Instance ID of affected instance
  -n, --no-console-output
                        Do not dump instance console output
  -a, --autoscaler-tasks
                        (Only) Query the autosscaler tasks for the SDDC instance
  -s, --host-state      Query the host state using RTS script
  -p {1,3,6,12,24,36,48,72}, --time-period {1,3,6,12,24,36,48,72}
                        Time range in hours to search for AWS cloudwatch metrics
  -h, --help
```

**Note**: The option to query the host state using RTS requires intranet (VPN) access as RTS service is only available on the intranet

**Example**:
```
$ ./instance_failure.py -S 229a57ae-412e-4314-8171-ca443ac6f4b9 -I 172.21.242.137
Saving console output to file: /home/i-0bf1153c0acca0d61-console.txt

{'first_instance_status_failure': '2020-07-09 14:57:00+00:00',
 'first_system_status_failure': None,
 'hardware_error': False,
 'instance_id': 'i-0bf1153c0acca0d61',
 'instance_state': {u'Code': 16, u'Name': 'running'},
 'instance_status': [{u'ImpairedSince': '2020-07-09 14:57:00+00:00',
                      u'Name': 'reachability',
                      u'Status': 'failed'}],
 'instance_status_failure': True,
 'instance_type': 'i3.metal',
 'ip_address': '172.21.242.137',
 'last_instance_status_failure': '2020-07-09 15:07:00+00:00',
 'last_system_status_failure': None,
 'launch_time': '2020-01-29 15:12:08+00:00',
 'org_id': u'81c4922c-486c-4336-98b9-744e965aad88',
 'region': u'eu-west-2',
 'sddc_id': '229a57ae-412e-4314-8171-ca443ac6f4b9',
 'system_status': [{u'Name': 'reachability', u'Status': 'passed'}],
 'system_status_failure': False}

Recommendation:
{
  "Details": "Collect host and console logs and file a PR for investigation (Host PSOD)", 
  "Recommendation": "FILE_PR"
}
```

## instance_launch_time

This script queries the instances in a SDDC (or queries an instance matching a specific instanceID or IP address within the SDDC) and reports a short summary output, specifically the launch time of the instance.
```
usage: instance_launch_time.py -S SDDC_ID [-I IP_ADDRESS] [-i INSTANCE_ID]
                               [-h]

optional arguments:
  -S SDDC_ID, --sddc-id SDDC_ID
                        SDDC ID of the instance
  -I IP_ADDRESS, --ip-address IP_ADDRESS
                        IP Address of instance
  -i INSTANCE_ID, --instance-id INSTANCE_ID
                        Instance ID of instance
  -h, --help
```
**Example**:
```
$ ./instance_launch_time.py -S bd2ce819-d7dc-4860-8179-a9e4fb27b83e
('InstanceId', 'InstanceType', 'IPAddress', 'InstanceState', 'LaunchTime')
('i-082fd01b75da30dc4', 'i3.metal', '10.5.32.4', 'running', '2020-01-22 16:47:23+00:00')
('i-06ec68d4ae7e943ac', 'i3.metal', '10.5.32.6', 'running', '2020-01-22 16:47:26+00:00')
('i-0137d7b2b6af485fc', 'i3.metal', '10.5.32.5', 'running', '2020-01-22 16:47:24+00:00')
('i-036ed67830b722029', 'm5.xlarge', '10.5.144.4', 'running', '2020-05-18 05:03:05+00:00')
```

## get_sddc_task

This script queries the VMC tasks that were executed for a particular SDDC and reports the output in JSON format.
```
usage: get_sddc_tasks.py -S SDDC_ID [-t TASK_TYPE] [-s TASK_STATUS]
                         [-i TASK_ID] [-p {1,3,7,15,30,60,180}] [-h]


optional arguments:
  -S SDDC_ID, --sddc-id SDDC_ID
                        SDDC ID of the affected instance
  -t TASK_TYPE, --task-type TASK_TYPE
                        VMC Task Type
  -s TASK_STATUS, --task-status TASK_STATUS
                        VMC Task Status
  -i TASK_ID, --task-id TASK_ID
                        Get specific VMC taskID and exit
  -p {1,3,7,15,30,60,180}, --time-period {1,3,7,15,30,60,180}
                        Time range in days to retrieve SDDC tasks
  -h, --help
```
**Example**:
```
$ ./get_sddc_tasks.py -S 297860eb-f557-45cb-b156-1cf682bf6ff2 -t CLUSTER-DESTROY
  .
<snip>
  .
    "id": "04f0fa40-45b9-483a-8846-fef4fca27172", 
    "parent_notifications": null, 
    "service_errors": [], 
    "customer_error_message": null, 
    "task_type": "CLUSTER-DESTROY", 
    "user_id": "09411a8e-5dad-39ee-ae97-234a2ca02f7d", 
    "resource_id": "297860eb-f557-45cb-b156-1cf682bf6ff2", 
    "estimated_remaining_minutes": 0, 
    "start_resource_entity_version": 1103, 
    "end_resource_entity_version": 1106, 
    "version": 51, 
    "params": {
      "clusterForceRemove": true, 
      "clusterName": "Cluster-2", 
      "clusterOriginalState": "FAILED", 
      "clusterId": "16c4f1b4-9c9e-450d-b420-0261bdbda8b9", 
      "sddcWorkerTaskId": "aa719b42-e638-4115-ae33-ca13e290859c", 
      "clusterDeletePollCount": 44, 
      "sddcIdOfCluster": "297860eb-f557-45cb-b156-1cf682bf6ff2"
    }, 
  .
<snip>
    "end_time": "2021-02-22T17:07:45.668000Z", 
    "created_build_number": 0, 
    "resource_type": "sddc", 
    "task_sub_status_transitions": [
      {
        "new_sub_status": "POD_DELETE_CLUSTER", 
        "transition_time": "2021-02-22T16:56:23.783Z", 
        "old_sub_status": "STARTED"
      }, 
      {
        "new_sub_status": "POD_POLL_DELETE_CLUSTER", 
        "transition_time": "2021-02-22T16:56:23.893Z", 
        "old_sub_status": "POD_DELETE_CLUSTER"
      }, 
      {
        "new_sub_status": "DELETE_INSTANCES", 
        "transition_time": "2021-02-22T17:00:50.442Z", 
        "old_sub_status": "POD_POLL_DELETE_CLUSTER"
      }, 
      {
        "new_sub_status": "FINISHED", 
        "transition_time": "2021-02-22T17:07:45.639Z", 
        "old_sub_status": "DELETE_INSTANCES"
      }
    ]
  }
```
