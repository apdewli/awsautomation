# awsautomation
# This automation tools is for creation of new Child Account in AWS Organization. 

account-create-cf-template.json is the base CloudFormation whih is use the email id as input parameter for the new account. The CloudFormation template will use custom resource to trigger the lambda fuction to create the new account. After the creation of the new account the tool perform below actiion on the new account.
  1. Create New OU in the organization and move that acount to new OU.
  2. Delete defalt VPC in all regions in that account.
  3. Create federated IAM role in the new account and associate it with AD for federation.
  
# The project includes cloudformation templates for below tasks also.
  1. Enabling CloudTrail and AWS Config in new AWS account.
  2. Automation for tagging on EC2 instance while creation of the new EC2 instance.
  
