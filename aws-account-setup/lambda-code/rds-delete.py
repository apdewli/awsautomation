from __future__ import print_function
import boto3
import datetime
import botocore
import time
import sys
import argparse
import os
import urllib
import json
from botocore.vendored import requests
from urllib.parse import urlparse


def delete_rds(dbinstanceidentifier):
    rds_client = boto3.client('rds')
    try:
        db_instance_response = rds_client.describe_db_instances(DBInstanceIdentifier=dbinstanceidentifier)
        db_instance_status = db_instance_response['DBInstances'][0]['DBInstanceStatus']

        if db_instance_status == 'available':
            print("Deleting rds database " + dbinstanceidentifier)
            deleting_rds = True
            try:
                while deleting_rds is True:
                    try:
                        deleting_rds = False
                        delete_rds_response = rds_client.delete_db_instance(
                                DBInstanceIdentifier=dbinstanceidentifier,
                                SkipFinalSnapshot=True,
                                DeleteAutomatedBackups=False
                            )
                    except botocore.exceptions.ClientError as e:
                        deleting_rds = True
                        print(e)
                        print("Waiting for the RDS to get deleted...")
                        time.sleep(60)

                rds_deleted = True
                print("RDS deletion in process...")
                print(delete_rds_response)
                while rds_deleted is True:
                    try:
                        db_response = rds_client.describe_db_instances(DBInstanceIdentifier=dbinstanceidentifier)
                        db_status = db_response['DBInstances'][0]['DBInstanceStatus']
                        if db_status :
                            print("Waiting for the RDS to get deleted . . .")
                            time.sleep(60)
                        else:
                            rds_deleted = False
                            print("RDS instance deleted")
                            return "Success"
                            
                    except botocore.exceptions.ClientError as e:
                        rds_deleted = False
                        print("RDS instance deleted")
                        return "Success"

            except botocore.exceptions.ClientError as e:
                print("Error in deleting the rds db instance.Error : {}".format(e))
                return e

        else:
            #print("RDS is not in available state.")
            return "RDS is not in available state."

    except botocore.exceptions.ClientError as e:
        print("Unable to find the database instance.Error : {}".format(e))
        return "Failed to check the db instance status becuse of above error!"



def respond_cloudformation(event, status, data=None):
    responseBody = {
        'Status': status,
        'Reason': 'See the details in CloudWatch Log Stream',
        'PhysicalResourceId': event['ServiceToken'],
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data
    }

    print('Response = ' + json.dumps(responseBody))
    print(event)
    requests.put(event['ResponseURL'], data=json.dumps(responseBody))


def lambda_handler(event,context):
    print(event)
    my_session = boto3.session.Session()
    stackregion = my_session.region_name

    acid_client = boto3.client("sts")
    master_account_id = acid_client.get_caller_identity()["Account"]

    dbinstanceidentifier = os.environ['dbinstanceidentifier']

    try:
        rds_delete_status = delete_rds(dbinstanceidentifier)

        if rds_delete_status == "Success":
            respond_cloudformation(event, "SUCCESS", { "Message" : "RDS instance deleted successfully."})
            print("RDS deleted successfully")

        else:
            print(rds_delete_status)

    except botocore.exceptions.ClientError as e:
        print("Error in deleting the rds db instance.Error : {}".format(e))
        return "Failed to delete the DB instance because of above error!"