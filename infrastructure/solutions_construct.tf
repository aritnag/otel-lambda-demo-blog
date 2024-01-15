provider "aws" {
  region = "eu-west-1"
  default_tags {
    tags = {
      Name = "Otel-Serverless-Demo"
    }
  }
}


variable "secret_id" {
  type    = string
  default = "documentdbdemooteltest"
}

data "aws_availability_zones" "available" {}

data "aws_ami" "amazon_linux_2" {
  most_recent = true

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "name"
    values = ["amzn2-ami-ecs-hvm-*-x86_64-ebs"]
  }

  owners = ["amazon"]
}


resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_subnet" "public_subnet" {
  count             = 1
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.0.0/24"
  availability_zone = element(data.aws_availability_zones.available.names, 0)

  map_public_ip_on_launch = true

  tags = {
    Name = "Otel-Serverless-Demo"
  }
}
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "Otel-Serverless-Public-Route-Table"
  }
}

resource "aws_route" "internet_access_route" {
  route_table_id         = aws_route_table.public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}

resource "aws_route_table_association" "public_subnet_association" {
  subnet_id      = aws_subnet.public_subnet[0].id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_subnet" "private_subnet" {
  count             = 2
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = element(data.aws_availability_zones.available.names, count.index)

  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.nat_gateway.id
  subnet_id     = aws_subnet.public_subnet[0].id
  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway.id
  }

  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_route_table_association" "private_subnet_association" {
  count          = 2
  subnet_id      = aws_subnet.private_subnet[count.index].id
  route_table_id = aws_route_table.private_route_table.id

}

resource "aws_security_group" "nat_sg" {
  name        = "nat-sg"
  description = "Security group for NAT gateway"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    description = "Allow all inbound traffic"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    description = "Allow all outbound traffic"
    cidr_blocks = ["0.0.0.0/0"]
  }

  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_instance" "nat_instance" {
  count         = 1
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public_subnet[0].id

  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_network_interface" "nat_interface" {
  subnet_id = aws_subnet.public_subnet[0].id

  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_network_interface_attachment" "nat_attachment" {
  instance_id          = aws_instance.nat_instance[0].id
  network_interface_id = aws_network_interface.nat_interface.id
  device_index         = 1

}

resource "aws_eip" "nat_gateway" {
}

resource "aws_vpc_endpoint" "secrets_manager_endpoint" {
  vpc_id            = aws_vpc.vpc.id
  service_name      = "com.amazonaws.eu-west-1.secretsmanager"
  vpc_endpoint_type = "Interface"

  security_group_ids  = [aws_security_group.sg_for_lambda.id]
  subnet_ids          = aws_subnet.private_subnet[*].id
  private_dns_enabled = true
  tags = {
    Name = "Otel-Serverless-Demo"
  }
}


resource "aws_docdb_cluster" "docdb_cluster" {
  cluster_identifier        = "demodatabase"
  vpc_security_group_ids    = [aws_security_group.sg_for_lambda.id]
  master_username           = "aritrademo"
  engine                    = "docdb" # Use "docdb" as the engine name
  master_password           = "aritrademo"
  db_subnet_group_name      = aws_db_subnet_group.docdb_subnet_group.name
  final_snapshot_identifier = "demodatabase-final-snapshot" # Specify a name for the final snapshot
  skip_final_snapshot       = true
  tags = {
    Name = "Otel-Serverless-Demo"
  } # Skip the final snapshot
}
resource "aws_docdb_cluster_instance" "docdb_cluster_instance" {
  identifier         = "aritrademodatabase" # You can provide a unique identifier for each instance
  cluster_identifier = aws_docdb_cluster.docdb_cluster.id
  instance_class     = "db.r5.large" # Set the desired instance type
  tags = {
    Name = "Otel-Serverless-Demo"
  }

}

resource "aws_db_subnet_group" "docdb_subnet_group" {
  name       = "docdb-subnet-group"
  subnet_ids = aws_subnet.private_subnet[*].id
  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_security_group" "docdb_sg" {
  name        = "docdb-sg"
  description = "Allow DocumentDB access from VPC"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.vpc.cidr_block]
  }
  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_apigatewayv2_api" "http_api" {
  name          = "ApiGatewqyToLambda"
  protocol_type = "HTTP"
  tags = {
    Name = "Otel-Serverless-Demo"
  }
}
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com", "apigateway.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }

}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "LambdaBasicExecutionPolicy"
  description = "Policy for Lambda to write logs to CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
        ],
        Resource = "*",
      },
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:*",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds",
        ],
        Resource = [aws_secretsmanager_secret.docdb_secret.arn],
      }
    ],
  })
}


resource "aws_iam_role_policy_attachment" "lambda_execution_policy_attachment" {
  policy_arn = aws_iam_policy.lambda_policy.arn
  role       = aws_iam_role.iam_for_lambda.name
}
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/../lambda/app.zip"
}
resource "aws_iam_role_policy" "lambda_execution_role_policy" {
  name = "LambdaExecutionRolePolicy"
  role = aws_iam_role.iam_for_lambda.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "ec2:*",
        ],
        Effect   = "Allow",
        Resource = "*",
      },
    ],
  })
}

resource "aws_lambda_function" "lambda_function" {
  function_name    = "LambdaToDocumentDB"
  runtime          = "python3.8"
  role             = aws_iam_role.iam_for_lambda.arn
  handler          = "lambda_handler.lambda_handler"
  timeout          = 900
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = filebase64("${path.module}/../lambda/lambda_handler.py")
  provisioner "local-exec" {
    command = "pip3 install -r ${path.module}/../lambda/requirements.txt -t ${path.module}/../lambda"
  }
  depends_on = [data.archive_file.lambda_zip]
  tracing_config {
    mode = "Active"
  }
  layers = ["arn:aws:lambda:eu-west-1:901920570463:layer:aws-otel-python-amd64-ver-1-21-0:1"]
  environment {
    variables = {
      DOCUMENTDB_SECRET_NAME              = "${var.secret_id}"
      AWS_LAMBDA_EXEC_WRAPPER             = "/opt/otel-instrument"
      OTEL_PROPAGATORS                    = "xray"
      OPENTELEMETRY_COLLECTOR_CONFIG_FILE = "/var/task/collector.yaml"
    }
  }

  vpc_config {
    subnet_ids         = aws_subnet.private_subnet[*].id
    security_group_ids = [aws_security_group.sg_for_lambda.id]
  }
  tags = {
    Name = "Otel-Serverless-Demo"
  }

}


resource "aws_security_group" "sg_for_lambda" {
  name        = "demo-sg-for-lambda"
  description = "Security group for Lambda function"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    description = "Allow all inbound traffic"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    description = "Allow all outbound traffic"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Otel-Serverless-Demo"
  }
}


resource "aws_secretsmanager_secret" "docdb_secret" {
  name = var.secret_id
  tags = {
    Name = "Otel-Serverless-Demo"
  }
}

resource "aws_secretsmanager_secret_version" "docdb_secret_version" {
  secret_id = aws_secretsmanager_secret.docdb_secret.id
  secret_string = jsonencode({
    cluster_identifier        = aws_docdb_cluster.docdb_cluster.cluster_identifier,
    master_username           = aws_docdb_cluster.docdb_cluster.master_username,
    host                      = aws_docdb_cluster.docdb_cluster.endpoint,
    port                      = 27017,
    engine                    = aws_docdb_cluster.docdb_cluster.engine,
    master_password           = aws_docdb_cluster.docdb_cluster.master_password,
    db_subnet_group_name      = aws_db_subnet_group.docdb_subnet_group.name,
    final_snapshot_identifier = aws_docdb_cluster.docdb_cluster.final_snapshot_identifier,
    skip_final_snapshot       = aws_docdb_cluster.docdb_cluster.skip_final_snapshot,
  })

}


resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id             = aws_apigatewayv2_api.http_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.lambda_function.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "default_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

resource "aws_apigatewayv2_stage" "api_stage" {
  api_id = aws_apigatewayv2_api.http_api.id

  name        = "demo" # You can customize the stage name
  auto_deploy = true
}

resource "aws_apigatewayv2_deployment" "api_deployment" {
  api_id     = aws_apigatewayv2_api.http_api.id
  depends_on = [aws_apigatewayv2_stage.api_stage]
}
resource "aws_lambda_permission" "lambda_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
  depends_on = [aws_apigatewayv2_api.http_api, aws_lambda_function.lambda_function]

}


resource "aws_cloudwatch_query_definition" "db_insert" {
  name = "DocumentDB_Inserts"

  log_group_names = [
    "/aws/lambda/${aws_lambda_function.lambda_function.function_name}"
  ]

  query_string = <<EOF
fields @timestamp, @message, @logStream, @log
      | filter (@message like /mydb\.insert/)
      | sort @timestamp desc
      | limit 20
      | stats count() by bin(1h)
EOF
}
resource "aws_cloudwatch_query_definition" "db_delete" {
  name = "DocumentDB_Deletes"

  log_group_names = [
    "/aws/lambda/${aws_lambda_function.lambda_function.function_name}"
  ]

  query_string = <<EOF
fields @timestamp, @message, @logStream, @log
      | filter (@message like /mydb\.delete/)
      | sort @timestamp desc
      | limit 20
      | stats count() by bin(1h)
EOF
}


resource "aws_cloudwatch_dashboard" "otel_serverless_demo" {
  dashboard_name = "otel_serverless_demo"
  dashboard_body = <<-EOF
{
    "widgets": [
        {
            "type": "log",
            "x": 0,
            "y": 24,
            "width": 24,
            "height": 6,
            "properties": {
                "region": "eu-west-1",
                "title": "Lambda Logs",
                "query": "SOURCE '/aws/lambda/${aws_lambda_function.lambda_function.function_name}'| fields @timestamp, @message, @logStream | sort @timestamp desc ",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 24,
            "width": 6,
            "height": 6,
            "properties": {
                "region": "eu-west-1",
                "title": "DocumentDB Inserts",
                "query": "SOURCE '/aws/lambda/${aws_lambda_function.lambda_function.function_name}'| fields @timestamp, @message, @logStream, @log | filter (@message like  /mydb\\.insert/) | sort @timestamp desc | limit 20 | stats count() ",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 6,
            "y": 24,
            "width": 6,
            "height": 6,
            "properties": {
                "region": "eu-west-1",
                "title": "DocumentDB Deletes",
                "query": "SOURCE '/aws/lambda/${aws_lambda_function.lambda_function.function_name}'| fields @timestamp, @message, @logStream, @log | filter (@message like  /mydb\\.delete/) | sort @timestamp desc | limit 20 | stats count() ",
                "view": "table"
            }
        },
        {
            "type": "log",
            "x": 12,
            "y": 24,
            "width": 6,
            "height": 6,
            "properties": {
                "region": "eu-west-1",
                "title": "DocumentDB Finds",
                "query": "SOURCE '/aws/lambda/${aws_lambda_function.lambda_function.function_name}'| fields @timestamp, @message, @logStream, @log | filter (@message like  /mydb\\.find/) | sort @timestamp desc | limit 20 | stats count() ",
                "view": "table"
            }
        }
    ]
}
EOF
  depends_on = [aws_cloudwatch_query_definition.db_delete, aws_cloudwatch_query_definition.db_insert]
}



resource "aws_cloudwatch_metric_alarm" "insert_count_alarm" {
  alarm_name          = "DocumentDBInsertsAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 5

  metric_name = "Count"
  namespace   = "CWAgent"
  period      = 300 # Set the same value as bin size in your CloudWatch Query

  dimensions = {
    LogGroupName = "/aws/lambda/${aws_lambda_function.lambda_function.function_name}"
    QueryName    = "DocumentDB_Inserts"
  }

  statistic = "Sum"

  alarm_actions = [aws_sns_topic.logmetricsalarmsns.arn] # Replace with your SNS topic ARN
}
resource "aws_sns_topic" "logmetricsalarmsns" {
  name = "logmetricsalarmsns"
}
resource "aws_sns_topic_subscription" "your_subscription" {
  topic_arn = aws_sns_topic.logmetricsalarmsns.arn
  protocol  = "email"                    # Replace with the desired protocol (e.g., "email", "http", "https", etc.)
  endpoint  = "aritra@playgroundtech.io" # Replace with your actual email address or endpoint
}
output "api_gateway_url" {
  value       = aws_apigatewayv2_stage.api_stage.invoke_url
  description = "The URL of the deployed API Gateway stage"
}
