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

def get_client(service):
  client = boto3.client(service)
  return client

#Create new AWS account.

def create_account(event,accountname,accountemail,accountrole,access_to_billing,scp,root_id):
    account_id = 'None'
    client = get_client('organizations')


    try:
        print("Trying to create the account with {}".format(accountemail))
        create_account_response = client.create_account(Email=accountemail, AccountName=accountname,
                                                        RoleName=accountrole,
                                                        IamUserAccessToBilling=access_to_billing)
        while(create_account_response['CreateAccountStatus']['State'] is 'IN_PROGRESS'):
            print(create_account_response['CreateAccountStatus']['State'])
        time.sleep(40)
        account_status = client.describe_create_account_status(CreateAccountRequestId=create_account_response['CreateAccountStatus']['Id'])
        print("Account Creation status: {}".format(account_status['CreateAccountStatus']['State']))

        if(account_status['CreateAccountStatus']['State'] == 'FAILED'):
            print("Account Creation Failed. Reason : {}".format(account_status['CreateAccountStatus']['FailureReason']))
            delete_respond_cloudformation(event, "FAILED", "Account Creation Failed. Deleting Lambda Function. Reason : {}".format(account_status['CreateAccountStatus']['FailureReason']))
            sys.exit(1)

    except botocore.exceptions.ClientError as e:
        print("In the except module. Error : {}".format(e))
        delete_respond_cloudformation(event, "FAILED", "Account Creation Failed. Deleting Lambda Function.Reason : {}".format(account_status['CreateAccountStatus']['FailureReason']))

    time.sleep(10)
    create_account_status_response = client.describe_create_account_status(CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
    account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')

    while(account_id is None ):
        create_account_status_response = client.describe_create_account_status(CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
        account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')

    return(create_account_response,account_id)



def assume_role(account_id, accountrole):
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + accountrole
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(60)

    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']


#Create S3 bucket to store CF templates in new account.
def create_bucket(credentials, account_id, s3_source_bucket, stackregion, accountrole, lambdarolearn):
    s3_source_client = boto3.client('s3')
    s3_target_client = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)
    s3_target_resource = boto3.resource('s3', aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)
    timestr = time.strftime("%Y%m%d%H%M%S")
    s3_target_bucket_name = "cf-templates-"+account_id+"-"+timestr
    print (s3_target_bucket_name)
    print(stackregion)
    try:
        if(stackregion == 'us-east-1'):
           s3_target_bucket_location = s3_target_client.create_bucket(Bucket=s3_target_bucket_name).get('Location')
           print(s3_target_bucket_location)
           s3_target_bucket = s3_target_bucket_location.split('/')[1]
        else:
            s3_target_bucket_location = s3_target_client.create_bucket(Bucket=s3_target_bucket_name, CreateBucketConfiguration={
            'LocationConstraint': stackregion}).get('Location')
            url = urlparse(s3_target_bucket_location)
            print(url)
            s3_target_bucket = url.hostname.split('.')[0]


        bucket_creation = True
        while bucket_creation is True:
            bucket_status = s3_target_resource.Bucket(s3_target_bucket)
            print(bucket_status)
            if bucket_status.creation_date:
                print("The bucket exists")
                bucket_creation = False
            else:
                print("The bucket does not exist")
                time.sleep(10)

        #Create Bucket policy for the newly created S3 bucket.

        bucket_policy = {
              "Id": "Policy1596865251713",
              "Version": "2012-10-17",
               "Statement": [
                   {
                       "Sid": "Stmt1596865213314",
                        "Action": "s3:*",
                        "Effect": "Allow",
                        "Resource": "arn:aws:s3:::%s/*" % s3_target_bucket,
                        "Principal": {
                             "AWS": [
                                  "arn:aws:sts::{0}:assumed-role/{1}/NewAccountRole".format(account_id, accountrole),
                                  "{0}".format(lambdarolearn)
                                  ]
                            }
                    },
                    {
                        "Sid": "Stmt1596865249390",
                        "Action": [
                               "s3:GetObject"
                              ],
                        "Effect": "Allow",
                        "Resource": "arn:aws:s3:::%s/*" % s3_target_bucket,
                        "Principal": "*"
                    }
                ]
        }

        print (s3_target_bucket)
        bucket_policy = json.dumps(bucket_policy)
        s3_target_client.put_bucket_policy(Bucket=s3_target_bucket, Policy=bucket_policy)
        return s3_target_bucket

    except botocore.exceptions.ClientError as e:
        print("Error Creating the S3 bucket.Error : {}".format(e))
        return e


def copy_files_to_new_bucket(s3_source_bucket, s3_target_bucket, credentials, stackregion):
    try:
        s3_source_client = boto3.client('s3')
        s3_target_client = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)
        for file in s3_source_client.list_objects(Bucket=s3_source_bucket)['Contents']:
            print(file['Key'])
            copy_source = {'Bucket':s3_source_bucket, 'Key':file['Key']}
            print(copy_source)
            s3_source_client.copy_object(ACL='public-read', Bucket=s3_target_bucket, Key=file['Key'], CopySource=copy_source)
    except botocore.exceptions.ClientError as e:
        print("Error copying files to S3 bucket.Error : {}".format(e))
        return e

def get_ou_name_id(root_id,organization_unit_name):

    ou_client = get_client('organizations')
    list_of_OU_ids = []
    list_of_OU_names = []
    ou_name_to_id = {}

    list_of_OUs_response = ou_client.list_organizational_units_for_parent(ParentId=root_id)

    for i in list_of_OUs_response['OrganizationalUnits']:
        list_of_OU_ids.append(i['Id'])
        list_of_OU_names.append(i['Name'])

    if(organization_unit_name not in list_of_OU_names):
        print("The provided Organization Unit Name doesn't exist. Creating an OU named: {}".format(organization_unit_name))
        try:
            ou_creation_response = ou_client.create_organizational_unit(ParentId=root_id,Name=organization_unit_name)
            for k,v in ou_creation_response.items():
                for k1,v1 in v.items():
                    if(k1 == 'Name'):
                        organization_unit_name = v1
                    if(k1 == 'Id'):
                        organization_unit_id = v1
        except botocore.exceptions.ClientError as e:
            print("Error in creating the OU: {}".format(e))
            respond_cloudformation(event, "FAILED", { "Message": "Could not list out AWS Organization OUs. Account creation Aborted."})

    else:
        for i in range(len(list_of_OU_names)):
            ou_name_to_id[list_of_OU_names[i]] = list_of_OU_ids[i]
        organization_unit_id = ou_name_to_id[organization_unit_name]

    return(organization_unit_name,organization_unit_id)

def delete_default_vpc(credentials,currentregion):
    #print("Default VPC deletion in progress in {}".format(currentregion))
    ec2_client = boto3.client('ec2',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=currentregion)

    vpc_response = ec2_client.describe_vpcs()
    for i in range(0,len(vpc_response['Vpcs'])):
        if((vpc_response['Vpcs'][i]['InstanceTenancy']) == 'default'):
            default_vpcid = vpc_response['Vpcs'][0]['VpcId']

    subnet_response = ec2_client.describe_subnets()
    subnet_delete_response = []
    default_subnets = []
    for i in range(0,len(subnet_response['Subnets'])):
        if(subnet_response['Subnets'][i]['VpcId'] == default_vpcid):
            default_subnets.append(subnet_response['Subnets'][i]['SubnetId'])
    for i in range(0,len(default_subnets)):
        subnet_delete_response.append(ec2_client.delete_subnet(SubnetId=default_subnets[i],DryRun=False))

    #print("Default Subnets" + currentregion + "Deleted.")

    igw_response = ec2_client.describe_internet_gateways()
    for i in range(0,len(igw_response['InternetGateways'])):
        for j in range(0,len(igw_response['InternetGateways'][i]['Attachments'])):
            if(igw_response['InternetGateways'][i]['Attachments'][j]['VpcId'] == default_vpcid):
                default_igw = igw_response['InternetGateways'][i]['InternetGatewayId']
    #print(default_igw)
    detach_default_igw_response = ec2_client.detach_internet_gateway(InternetGatewayId=default_igw,VpcId=default_vpcid,DryRun=False)
    delete_internet_gateway_response = ec2_client.delete_internet_gateway(InternetGatewayId=default_igw)

    #print("Default IGW " + currentregion + "Deleted.")

    time.sleep(10)
    delete_vpc_response = ec2_client.delete_vpc(VpcId=default_vpcid,DryRun=False)
    print("Deleted Default VPC in {}".format(currentregion))
    return delete_vpc_response

def selfinvoke(event,status):
    lambda_client = boto3.client('lambda')
    function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    event['RequestType'] = status
    print('invoking itself ' + function_name)
    response = lambda_client.invoke(FunctionName=function_name, InvocationType='Event',Payload=json.dumps(event))



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


def delete_respond_cloudformation(event, status, message):
    responseBody = {
        'Status': status,
        'Reason': message,
        'PhysicalResourceId': event['ServiceToken'],
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId']
    }

    requests.put(event['ResponseURL'], data=json.dumps(responseBody))
    lambda_client = get_client('lambda')
    function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    print('Deleting resources and rolling back the stack.')
    time.sleep(60)
    lambda_client.delete_function(FunctionName=function_name)


def deploy_stacks(credentials, stackname, federation_file, s3_target_bucket, federation_provider_name, federation_access_role_name, account_id, notification_email_id, stackregion, templates_path, master_account_id, passwordhardexpiry):
    cf_client = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)

    template_url = "https://s3."+stackregion+".amazonaws.com/"+s3_target_bucket+"/"+templates_path+"/account-setup-master-template.json"
    print("Creating stack " + stackname + " in " + account_id + " using the template url " + template_url)
    creating_stack = True
    try:
        while creating_stack is True:
            try:
                creating_stack = False
                create_stack_response = cf_client.create_stack(
                    StackName=stackname,
                    TemplateURL= template_url,
                    Parameters=[
                        {
                            'ParameterKey' : 'TemplatS3bucket',
                            'ParameterValue' : s3_target_bucket
                        },
                        {
                            'ParameterKey' : 'StackRegion',
                            'ParameterValue' : stackregion
                        },
                        {
                            'ParameterKey' : 'TemplatPath',
                            'ParameterValue' : templates_path
                        },
                        {
                            'ParameterKey' : 'MasterAccountNumber',
                            'ParameterValue' : master_account_id
                        },
                        {
                            'ParameterKey' : 'FederationName',
                            'ParameterValue' : federation_provider_name
                        },
                                                {
                            'ParameterKey' : 'FederationMetadaBucket',
                            'ParameterValue' : s3_target_bucket
                        },
                        {
                            'ParameterKey' : 'FederationFile',
                            'ParameterValue' : federation_file
                        },
                        {
                            'ParameterKey' : 'NotificationEmail',
                            'ParameterValue' : notification_email_id
                        },
                                                {
                            'ParameterKey' : 'FederationRoleName',
                            'ParameterValue' : federation_access_role_name
                        },
                                                {
                            'ParameterKey' : 'HardExpiry',
                            'ParameterValue' : passwordhardexpiry
                        }
                    ],
                    NotificationARNs=[],
                    Capabilities=[
                        'CAPABILITY_NAMED_IAM',
                                                'CAPABILITY_AUTO_EXPAND'
                    ],
                    OnFailure='ROLLBACK',
                    Tags=[
                        {
                            'Key': 'ManagedResource',
                            'Value': 'True'
                        }
                    ]
                )
            except botocore.exceptions.ClientError as e:
                creating_stack = True
                print(e)
                print("Retrying...")
                time.sleep(10)

        stack_building = True
        print("Stack creation in process...")
        print(create_stack_response)
        while stack_building is True:
            event_list = cf_client.describe_stack_events(StackName=stackname).get("StackEvents")
            stack_event = event_list[0]

            if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
               stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
                stack_building = False
                print("Stack construction complete.")
            elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
                  stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
                stack_building = False
                print("Stack construction failed.")
                #sys.exit(1)
            else:
                print(stack_event)
                print("Stack building . . .")
                time.sleep(10)
        stack = cf_client.describe_stacks(StackName=stackname)
        return stack
    except botocore.exceptions.ClientError as e:
        print("Error deploying stack.There might be an error either accessing the Source bucket or accessing the baseline template from the source bucket.Error : {}".format(e))
        return e

def create_sns_topic(notification_email_id):
    sns_client = boto3.client('sns')

    topic_name = "AccountSetupTopic"
    topic_arn = sns_client.create_topic(Name=topic_name,
        Attributes={
            'DisplayName': 'AccountSetup'
        },
        Tags=[
            {
               'Key': "Name",
               'Value': topic_name
            },
        ]
    ).get('TopicArn')

    subscript_topic_arn = sns_client.subscribe(TopicArn=topic_arn, Protocol= 'email', Endpoint= notification_email_id , ReturnSubscriptionArn=True)

    return topic_arn



def send_notification(topic_arn, data):
    sns_client = boto3.client('sns')


    sns_client.publish(TargetArn=topic_arn,Message=data)

def create_ad_group(federation_access_role_name, managed_instance_id, account_id, accountname):

    groupname = "AWS-"+ account_id + "-" + federation_access_role_name


    ssm_client = boto3.client('ssm')
    ssmresponse = ssm_client.send_command(
        InstanceIds=[
            managed_instance_id,
        ],
        DocumentName='CreateAdGroup',
        TimeoutSeconds=120,
        Parameters={
            'adgroupname': [ groupname ],
            'accountprefix': [ accountname ]
        },
        CloudWatchOutputConfig={
        'CloudWatchLogGroupName': 'createAdGroupLogs',
        'CloudWatchOutputEnabled': True
        },
        MaxConcurrency='1',
        MaxErrors='1'
    )

def copy_ami(credentials, ami_source_region, ami_destination_region, account_id, ami_filter_tag_name, ami_filter_tag_value, master_account_id):
    copy_client_source = boto3.client('ec2',region_name=ami_source_region)
    copy_client_target = boto3.client('ec2', aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=ami_destination_region)
    try:
        ami_filter = [{
        'Name':'tag:'+ami_filter_tag_name,
        'Values': [ami_filter_tag_value]}]

        ami_response = copy_client_source.describe_images(Filters=ami_filter)

        for ami in ami_response['Images']:
            ami_name = ami['Name']
            ami_id = ami['ImageId']
            copy_client_source.modify_image_attribute(
                    Attribute='launchPermission',
                    ImageId=ami_id,
                    OperationType='add',
                    UserIds=[account_id]
                )

            source_ec2 = boto3.resource('ec2')
            source_ami = source_ec2.Image(ami_id)
            #print(source_ami)
            try:
                devlst = []
                devlst = source_ec2.Image(ami_id).block_device_mappings
                for dev in devlst:
                        dname = dev['DeviceName'][5:]
                        snapshotid = dev['Ebs']['SnapshotId']
                        print(snapshotid)
                        copy_client_source.modify_snapshot_attribute(
                                Attribute='createVolumePermission',
                                SnapshotId=snapshotid,
                                OperationType='add',
                                UserIds=[account_id]
                            )
            except botocore.exceptions.ClientError as e:
                print("An error occurred while sharing snapshots {}.".format(e))

            try:
                copy_client_target.copy_image(
                        Description='Copied AMI from Master Account.',
                        Name=ami_name+'-copied-ami-from-'+master_account_id,
                        SourceImageId=ami_id,
                        SourceRegion=ami_source_region,
                    )

            except botocore.exceptions.ClientError as e:
                print("An error occurred while copying the image {}.".format(e))


            print(ami_name, ami_id)

    except botocore.exceptions.ClientError as e:
        print("An error occurred while copying the image {}.".format(e))



def delete_bucket_policy(credentials, stackregion, s3_target_bucket):
    s3_target_client = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)
    print ("Updating S3 bucket policy in target account. for s3 bucket "+s3_target_bucket+" in "+stackregion+" region")
    try:
        s3_target_client.delete_bucket_policy(Bucket=s3_target_bucket)
        return s3_target_bucket

    except botocore.exceptions.ClientError as e:
        print("Error in deleting policy : {}".format(e))
        return e

def lambda_handler(event,context):
    print(event)
    my_session = boto3.session.Session()
    stackregion = my_session.region_name

    acid_client = boto3.client("sts")
    master_account_id = acid_client.get_caller_identity()["Account"]

    client = get_client('organizations')
    scp = None
    access_to_billing = "ALLOW"
    accountname = os.environ['accountname']
    accountemail = os.environ['accountemail']
    accountrole = accountname
    organization_unit_name = accountname
    s3_source_bucket = os.environ['sources3bucket']
    stackname = os.environ['stackname']
    cross_account_role_name = accountname
    federation_file = os.environ['federation_file']
    federation_provider_name = "ossamladfs"
    federation_access_role_name = "Custom-ADFS-"+accountname
    notification_email_id = os.environ['notification_email_id']
    templates_path = "cf-templates"
    lambdarolearn = os.environ['lambdarolearn']
    managed_instance_id = os.environ['managed_instance_id']
    passwordhardexpiry = os.environ['passwordhardexpiry']
    ami_source_region = os.environ['ami_source_region']
    ami_destination_region = os.environ['ami_destination_region']
    ami_filter_tag_name = os.environ['ami_filter_tag_name']
    ami_filter_tag_value = os.environ['ami_filter_tag_value']





    if (event['RequestType'] == 'Create'):
        selfinvoke(event,'Wait')
        top_level_account = event['ServiceToken'].split(':')[4]
        org_client = get_client('organizations')

        try:
            list_roots_response = org_client.list_roots()
            print(list_roots_response)
            root_id = list_roots_response['Roots'][0]['Id']
        except:
            root_id = "Error"

        if root_id  is not "Error":
            print("Creating new account: " + accountname + " (" + accountemail + ")")


            (create_account_response,account_id) = create_account(event,accountname,accountemail,accountrole,access_to_billing,scp,root_id)
            print(create_account_response)

            print("Created acount:{}\n".format(account_id))


            credentials = assume_role(account_id, accountrole)

            time.sleep(120)

            topic_arn = create_sns_topic(notification_email_id)

            #ou_name =  get_ou_name_id(root_id,organization_unit_name)

            s3_target_bucket = create_bucket(credentials, account_id, s3_source_bucket, stackregion, accountrole, lambdarolearn)

            copy_files_to_new_bucket(s3_source_bucket, s3_target_bucket, credentials, stackregion)

            master_role_arn = 'arn:aws:iam::' + account_id + ':role/' + accountrole

            regions = []
            ec2_client = boto3.client('ec2')
            regions_response = ec2_client.describe_regions()
            for i in range(0,len(regions_response['Regions'])):
                regions.append(regions_response['Regions'][i]['RegionName'])
            for r in regions:
                try:
                    #print('In the VPC deletion block - {}'.format(r))
                    delete_vpc_response = delete_default_vpc(credentials,r)
                except botocore.exceptions.ClientError as e:
                    print("An error occurred while deleting Default VPC in {}. Error: {}".format(r,e))
                    i+=1

            if(organization_unit_name!='None'):
                try:
                    (organization_unit_name,organization_unit_id) = get_ou_name_id(root_id,organization_unit_name)
                    move_response = org_client.move_account(AccountId=account_id,SourceParentId=root_id,DestinationParentId=organization_unit_id)

                except Exception as ex:
                    template = "An exception of type {0} occurred. Arguments:\n{1!r} "
                    message = template.format(type(ex).__name__, ex.args)
                    print(message)
            if scp is not None:
                attach_policy_response = client.attach_policy(PolicyId=scp, TargetId=account_id)
                print("Attach policy response "+str(attach_policy_response))

            stack = deploy_stacks(credentials, stackname, federation_file, s3_target_bucket, federation_provider_name, federation_access_role_name, account_id, notification_email_id, stackregion, templates_path, master_account_id, passwordhardexpiry)

            ad_group_name = "AWS-"+ account_id +"-"+  federation_access_role_name

            respond_cloudformation(event, "SUCCESS", { "Message" : "New Account Created Successfully .",
                                                        "AccountId" : account_id,
                                                        "MasterIAMRole" : accountrole,
                                                        "MasterIAMRoleArn" : master_role_arn,
                                                        "s3BucketName" : s3_target_bucket,
                                                        "FederationRoleName": federation_access_role_name,
                                                        "ADGroupName": ad_group_name})


            data = "New AWS account created successfully with below detail:\n\nAccount ID - "+ account_id + "\nMaster IAM Role - "+ accountrole +"\nMaster IAM Role arn - "+ master_role_arn + "\ns3 Bucket Name - "+ s3_target_bucket +"\nFederation Role Name - " + federation_access_role_name + "\nAD Group Name - " + ad_group_name +"\n"
            send_notification(topic_arn, data)

            try:
                create_ad_group(federation_access_role_name, managed_instance_id, account_id, accountname)

            except botocore.exceptions.ClientError as e:
                    print("An error occurred while Creating the AD Group {}. Check SSM logs in S3 bucket".format(e))

            try:
                copy_ami(credentials, ami_source_region, ami_destination_region, account_id, ami_filter_tag_name, ami_filter_tag_value, master_account_id)

            except botocore.exceptions.ClientError as e:
                    print("An error occurred while copying the image {}.".format(e))

            try:
                delete_bucket_policy(credentials, stackregion, s3_target_bucket)

            except botocore.exceptions.ClientError as e:
                    print("An error occurred while copying the image {}.".format(e))

        else:
            print("Cannot access the AWS Organization ROOT. Contact the master account Administrator for more details.")
            #sys.exit(1)
            delete_respond_cloudformation(event, "FAILED", "Cannot access the AWS Organization ROOT. Contact the master account Administrator for more details.Deleting Lambda Function.")