import boto3
import json
import logging
import os
from botocore.vendored import requests
from botocore.exceptions import ClientError
import time


ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')
ram_client = boto3.client('ram')

SUCCESS = "SUCCESS"
FAILED = "FAILED"


def lambda_handler(event, context):
    response_data = {}
    setup_logging()
    log.info('In Main Handler')
    log.info(json.dumps(event))
    print(json.dumps(event))

    account = event['ResourceProperties']['Account']
    region = event['ResourceProperties']['Region']
    vpc_id = event['ResourceProperties']['Vpc_Id']
    cidr = event['ResourceProperties']['CIDR']
    tgw_arn = event['ResourceProperties']['Transit_Gateway_Arn']
    tgw_id = tgw_arn.split("/")[-1]

    if event['RequestType'] in ['Update', 'Create']:
        log.info('Event = ' + event['RequestType'])

        create_service_link_role()
        accept_tgw_sharing()
        vpc_metadata = get_vpc_metadata(account, region, vpc_id, cidr)
        tgw_status = check_transit_gateway_status(tgw_id)
        if tgw_status == 'available':
            create_transit_gateway_attatchment(vpc_id, tgw_id)
            create_vpc_route_to_tgw(vpc_metadata, tgw_id, cidr)
            send(event, context, 'SUCCESS', response_data)
        else:
            print("Transit Gateway Not found")
            send(event, context, 'FAILED', response_data)

    else:
        log.error("failed to run")
        send(event, context, 'FAILED', response_data)

    if event['RequestType'] in ['Delete']:
        log.info('Event = ' + event['RequestType'])
        send(event, context, 'SUCCESS', response_data)
        lambda_client = boto3.client('lambda')
        function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
        print('Deleting resources and rolling back the stack.')
        time.sleep(60)
        lambda_client.delete_function(FunctionName=function_name)


def check_transit_gateway_status(tgw_id):
    try:
        tgw_status_response = ec2_client.describe_transit_gateways(TransitGatewayIds=[tgw_id])
        tgw_status = tgw_status_response['TransitGateways'][0]['State']
        return tgw_status

    except Exception as e:
        print("Unable to find transit Gateway! Detailed Error: "+str(e))
        return None




def accept_tgw_sharing():
    try:
        tgw_ram_invitations = ram_client.get_resource_share_invitations()
        invitation = tgw_ram_invitations['resourceShareInvitations'][0]['resourceShareInvitationArn']
        print("New invitation found with id, "+invitation)
        ram_client.accept_resource_share_invitation(resourceShareInvitationArn=invitation)

    except Exception as e:
        print("Unable to accept transit Gateway sharing because of error: "+str(e))
        return None


def create_vpc_route_to_tgw(vpc_metadata, tgw_id, cidrs):
    response_data = {}

    for entry in vpc_metadata:
        if entry['Subnet']:

            try:
                describe_routes = ec2_client.describe_route_tables(
                    RouteTableIds=[entry['Route_Table']],
                )
                describe_routes = describe_routes['RouteTables']

                for cidr in cidrs.split(","):
                    cidr = cidr.strip()
                    for route in describe_routes[0]['Routes']:
                        if route['DestinationCidrBlock'] == cidr:

                            log.info('Deleting Route to ' + cidr + ' for ' + entry['Route_Table'] +' with a destination of ' + tgw_id)
                            print('Deleting Route to ' + cidr + ' for ' + entry['Route_Table'] +' with a destination of ' + tgw_id)
                            delete_existing_route = ec2_client.delete_route(
                                DestinationCidrBlock=cidr,
                                RouteTableId=entry['Route_Table']
                            )

                    log.info('Creating Route to ' + cidr + ' for ' + entry['Route_Table'] +' with a destination of ' + tgw_id)
                    print('Creating Route to ' + cidr + ' for ' + entry['Route_Table'] +' with a destination of ' + tgw_id)
                    create_route = ec2_client.create_route(
                        RouteTableId=entry['Route_Table'],
                        DestinationCidrBlock=cidr,
                        TransitGatewayId=tgw_id
                    )
                    log.info('Created Route to ' + cidr + ' for ' + entry['Route_Table'] +' with a destination of ' + tgw_id)
                    print('Created Route to ' + cidr + ' for ' + entry['Route_Table'] +' with a destination of ' + tgw_id)

            except Exception as e:
                log.error(e)
                return None


def create_transit_gateway_attatchment(vpc_id, tgw_id):
    try:
        tgw_response = ec2_client.describe_transit_gateway_vpc_attachments(Filters=[{'Name': 'vpc-id', 'Values':[ vpc_id ]},{'Name':'state','Values':['available']}])
        try:
            transit_gateway_attachment_id = tgw_response['TransitGatewayVpcAttachments'][0]['TransitGatewayAttachmentId']
            print('VPC with id, '+  vpc_id + ' is already attached to Transit Gateway, '+ tgw_id)
            log.info('VPC with id, '+  vpc_id + ' is already attached to Transit Gateway, '+ tgw_id)

        except:
            print('VPC with id, '+  vpc_id + ' is being attached to Transit Gateway, '+ tgw_id)
            log.info('VPC with id, '+  vpc_id + ' is being attached to Transit Gateway, '+ tgw_id)
            response = ec2_client.create_transit_gateway_vpc_attachment(
                TransitGatewayId=tgw_id,
                VpcId=vpc_id,
                SubnetIds=get_subnets(vpc_id)
            )
            time.sleep(90)
            print('VPC with id, '+  vpc_id + ' is attached to Transit Gateway, '+ tgw_id)
            log.info('VPC with id, '+  vpc_id + ' is attached to Transit Gateway, '+ tgw_id)


    except Exception as e:
        log.error(e)
        return None
        print('No subnets in VPC,' + vpc_id +' unable to attach VPC')
        log.info('No subnets in VPC,' + vpc_id +' unable to attach VPC')




def get_vpc_metadata(account, region, vpc_id, cidrs):


    returned_metadata = []

    try:
        get_vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        for vpc in get_vpc_response['Vpcs']:

            returned_vpc = vpc['VpcId']
            subnets = get_subnets(returned_vpc)
            for route_table in get_route_tables(returned_vpc,cidrs):
                metadata = {}
                #print("Route table id is "+route_table)
                metadata['Vpc'] = returned_vpc
                metadata['Subnet'] = subnets
                metadata['Route_Table'] = route_table
                #print(metadata)
                returned_metadata.append(metadata)

    except Exception as e:
        log.error(e)
        return None


    return returned_metadata


def get_subnets(returned_vpc):
    subnet_list = []
    az_subnet_mapping = []

    try:
        get_subnet_response = ec2_client.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [returned_vpc]
                }])

        for entry in get_subnet_response['Subnets']:
            subnet_list.append(entry['SubnetId'])

        for subnet in subnet_list:
            response = ec2_client.describe_subnets(
                Filters=[
                    {
                        'Name': 'subnet-id',
                        'Values': [subnet]
                    },
                ],
            )

            for sub in response['Subnets']:
                if not any(sub['AvailabilityZone'] in az for az in az_subnet_mapping):
                    az_subnet_mapping.append(
                        {sub['AvailabilityZone']: sub['SubnetId']})

    except Exception as e:
        log.error(e)
        return None

    subnets=[]

    for subnet_mapping in az_subnet_mapping:
        for key,value in subnet_mapping.items():
            subnets.append(value)

    return(subnets)


def get_route_tables(returned_vpc,cidrs):
    try:
        describe_route_tables = ec2_client.describe_route_tables(
            Filters=[
                {
                    'Name':'vpc-id',
                    'Values': [returned_vpc]
                }
            ]
        )
        route_table_metadata= []
        for route_tables in describe_route_tables['RouteTables']:
            route_table_id = route_tables['RouteTableId']
            #print(route_table_id)
            route_table_metadata.append(route_table_id)


            describe_routes = ec2_client.describe_route_tables(
               RouteTableIds=[
                   route_table_id,
               ],
            )
            describe_routes = describe_routes['RouteTables']

            for route in describe_routes[0]['Routes']:
                for cidr in cidrs.split(","):
                    cidr = cidr.strip()
                    if route['DestinationCidrBlock'] == cidr:

                        delete_existing_route = ec2_client.delete_route(
                            DestinationCidrBlock=cidr,
                            RouteTableId=route_table_id
                        )

    except Exception as e:
        log.error(e)
        return None

    return route_table_metadata


def create_service_link_role():
    service_role_exists = False

    list_roles = iam_client.list_roles(
    )

    for role in list_roles['Roles']:
        if role['RoleName'] == 'AWSServiceRoleForVPCTransitGateway':
            service_role_exists = True


    if not service_role_exists:
        create_role = iam_client.create_service_linked_role(
            AWSServiceName='transitgateway.amazonaws.com',
            )
        print(create_role)

    return()


def setup_logging():
    """Setup Logging."""
    global log
    log = logging.getLogger()
    log_levels = {'INFO': 20, 'WARNING': 30, 'ERROR': 40}

    if 'logging_level' in os.environ:
        log_level = os.environ['logging_level'].upper()
        if log_level in log_levels:
            log.setLevel(log_levels[log_level])
        else:
            log.setLevel(log_levels['ERROR'])
            log.error("The logging_level environment variable is not set \
                      to INFO, WARNING, or ERROR. \
                      The log level is set to ERROR")
    else:
        log.setLevel(log_levels['ERROR'])
        log.warning('The logging_level environment variable is not set.')
        log.warning('Setting the log level to ERROR')
    log.info('Logging setup complete - set to log level '
             + str(log.getEffectiveLevel()))


def send(event, context, responseStatus, response_data, physicalResourceId=None, noEcho=False):
    responseUrl = event['ResponseURL']

    #print(responseUrl)

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = response_data

    json_responseBody = json.dumps(responseBody)

    print("Response body:\n" + json_responseBody)

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