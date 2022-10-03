import boto3
import os
import json
from botocore.vendored import requests

org_client = boto3.client('organizations')
ram_client = boto3.client('ram')

def lambda_handler(event,context):
    print(event)
    response_data = {}
    my_session = boto3.session.Session()
    stackregion = my_session.region_name
    transit_gateway_arn = os.environ['transit_gateway_arn']
    
    
    
    try:
        share_transit_gateway(transit_gateway_arn)
        responseStatus = "SUCCESS"
        responde_to_cloudformation(event, context, responseStatus, response_data)
        
    except Exception as e:
        responseStatus = "FAILED"
        print("Error in sharing the transit Gateway! Error: "+str(e))
        
def share_transit_gateway(transit_gateway_arn):
    org_client = boto3.client('organizations')
    paginator = org_client.get_paginator('list_accounts')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for account in page['Accounts']:
            print(account['Id'])
            response = ram_client.create_resource_share(
                name='MasterAccountTransitGateway',
                resourceArns=[
                transit_gateway_arn
                ],
                principals=[
                    account['Id']
                    ],
                tags=[
                    {
                         'key': 'Name',
                        'value': 'MasterAccountTransitGateway'
                    },
                    ],
                allowExternalPrincipals=True
                )
                
def responde_to_cloudformation(event, context, responseStatus, response_data):
    responseUrl = event['ResponseURL']
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['PhysicalResourceId'] = event['ServiceToken']
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['Data'] = response_data

    json_responseBody = json.dumps(responseBody)

    print("Response body:" + json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))
