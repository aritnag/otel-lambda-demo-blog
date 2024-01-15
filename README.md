# Terraform AWS Infrastructure for Serverless Application

This Terraform script sets up a basic AWS infrastructure for a serverless application. The infrastructure includes a VPC with public and private subnets, an Internet Gateway, a NAT Gateway, an Amazon DocumentDB cluster, an API Gateway, and a Lambda function. The Lambda function interacts with the DocumentDB cluster, and the API Gateway provides a public interface to trigger the Lambda function.
## Solution Design
Here is the design of the solution construct
![Alt text](solutiondesign/Otel%20Implementation.png)

## Prerequisites
- AWS CLI installed and configured
- Terraform CLI installed

## Configuration

### AWS Provider
- Configures the AWS provider for the `eu-west-1` region.

```hcl
provider "aws" {
  region = "eu-west-1"
}
```

### Variables
- Defines a variable `secret_id` with a default value. This variable is used as the name for the DocumentDB cluster.

```hcl
variable "secret_id" {
  type    = string
  default = "documentdbblogdemo"
}
```

## Networking

### VPC
- Creates a VPC with DNS support and hostnames enabled.

```hcl
resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Otel-Serverless-Demo"
  }
}
```

### Internet Gateway
- Creates an Internet Gateway and associates it with the VPC.

```hcl
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "main"
  }
}
```

### Subnets
- Defines public and private subnets.

```hcl
resource "aws_subnet" "public_subnet" {
  count             = 1
  ...
}

resource "aws_subnet" "private_subnet" {
  count             = 2
  ...
}
```

### NAT Gateway
- Creates a NAT Gateway for private subnet communication.

```hcl
resource "aws_nat_gateway" "nat_gateway" {
  ...
}
```

### Route Table
- Defines route tables for private subnets.

```hcl
resource "aws_route_table" "private_route_table" {
  ...
}
```

## DocumentDB Cluster

### DocumentDB Cluster
- Creates an Amazon DocumentDB cluster.

```hcl
resource "aws_docdb_cluster" "docdb_cluster" {
  ...
}
```

### Security Groups
- Defines security groups for NAT Gateway and DocumentDB cluster.

```hcl
resource "aws_security_group" "nat_sg" {
  ...
}

resource "aws_security_group" "docdb_sg" {
  ...
}
```

## Serverless Components

### Lambda Function
- Sets up a Lambda function with necessary IAM roles and policies.

```hcl
resource "aws_lambda_function" "lambda_function" {
  ...
}
```

### API Gateway
- Configures an API Gateway to trigger the Lambda function.

```hcl
resource "aws_apigatewayv2_api" "http_api" {
  ...
}
```

### IAM Roles and Policies
- Defines IAM roles and policies for Lambda execution.

```hcl
resource "aws_iam_role" "iam_for_lambda" {
  ...
}

resource "aws_iam_policy" "lambda_policy" {
  ...
}
```

## Secrets Management

### Secrets Manager
- Sets up AWS Secrets Manager for storing secret information.

```hcl
resource "aws_secretsmanager_secret" "docdb_secret" {
  ...
}

resource "aws_secretsmanager_secret_version" "docdb_secret_version" {
  ...
}
```

## Deployment

### API Gateway Deployment
- Deploys the API Gateway.

```hcl
resource "aws_apigatewayv2_deployment" "api_deployment" {
  ...
}
```

### Lambda Permission
- Grants API Gateway permission to invoke the Lambda function.

```hcl
resource "aws_lambda_permission" "lambda_permission" {
  ...
}
```

## Outputs

### API Gateway URL
- Outputs the URL of the deployed API Gateway stage.

```hcl
output "api_gateway_url" {
  ...
}
```

## Usage

1. Make sure your AWS CLI is configured with the necessary credentials.
2. Install the Terraform CLI.
3. Run `terraform init` and `terraform apply` to create the infrastructure.

Remember to destroy the resources after usage by running `terraform destroy` to avoid unnecessary costs.