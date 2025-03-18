resource "aws_s3_bucket" "srseod-bucket" {
  bucket = "srseod-bucket"
}

resource "aws_s3_bucket_website_configuration" "srseod-bucket-web" {
  bucket = aws_s3_bucket.srseod-bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }

  routing_rule {
    condition {
      key_prefix_equals = "docs/"
    }
    redirect {
      replace_key_prefix_with = "documents/"
    }
  }
}

resource "aws_s3_object" "fluentbit-conf" {
  bucket     = aws_s3_bucket.srseod-bucket.bucket
  key        = "fluent-bit.conf"
  source     = "${path.module}/fluent-bit.conf"
  acl        = "private"
  kms_key_id = aws_kms_key.kms_key.arn
}

# NETWORK/ACCESS/GATEWAY/DB/ENCRYPTION
data "aws_s3_bucket" "sjteod-buckett" {
  bucket = "sjteod-buckett"
  lifecycle {
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "tf_state_lifecycle" {
  bucket = data.aws_s3_bucket.sjteod-buckett.id
  rule {
    id     = "PreventPermanentDeletion"
    status = "Enabled"

    filter {
      prefix = "ecs/"
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.83.1"
    }
  }
  backend "s3" { #### policy, versioning, lifecyccle, locking(s3/dynamodb)
    bucket  = "sjteod-buckett"
    key     = "ecs/terraform.tfstate"
    region  = "eu-west-2"
    encrypt = false
  }
}

provider "aws" {
  region  = local.region
  profile = "main"
}

resource "aws_vpc" "vpcgoose" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "vpcgoose"
  }
}

data "aws_availability_zones" "az" {}

resource "aws_subnet" "pub_subnet" {
  vpc_id            = aws_vpc.vpcgoose.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.az.names[0]

  tags = {
    Name = "pub_subnet"
  }
}

resource "aws_subnet" "pub_subnet1" {
  vpc_id            = aws_vpc.vpcgoose.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.az.names[1]

  tags = {
    Name = "pub_subnet1"
  }
}

resource "aws_subnet" "pri_subnet" {
  vpc_id            = aws_vpc.vpcgoose.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = data.aws_availability_zones.az.names[0]

  tags = {
    Name = "pri_subnet"
  }
}
resource "aws_subnet" "pri_subnet1" {
  vpc_id            = aws_vpc.vpcgoose.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = data.aws_availability_zones.az.names[1]

  tags = {
    Name = "pri_subnet1"
  }
}

resource "aws_db_subnet_group" "aurora_postgresql" {
  name = "aurora-postgresql-subnet-group"
  subnet_ids = [
    aws_subnet.pri_subnet.id,
    aws_subnet.pri_subnet1.id
  ]

  tags = {
    Name = "aurora_postgresql"
  }
}

# resource "aws_db_subnet_group" "aurora_postgresql" {
#   name = "aurora-postgresql-subnet-group"
#   subnet_ids = [
#     aws_subnet.pub_subnet.id,
#     aws_subnet.pub_subnet1.id
#   ]

#   tags = {
#     Name = "aurora_postgresql"
#   }
# }

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpcgoose.id

  tags = {
    Name = "${local.name}.igw"
  }
}

resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.vpcgoose.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "pub_rt_asso" {
  subnet_id      = aws_subnet.pub_subnet.id
  route_table_id = aws_route_table.pub_rt.id
}

resource "aws_route_table_association" "pub_rt_asso1" {
  subnet_id      = aws_subnet.pub_subnet1.id
  route_table_id = aws_route_table.pub_rt.id
}

resource "aws_eip" "eip" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pub_subnet.id
  tags = {
    Name = "nat"
  }
  depends_on = [aws_internet_gateway.igw]
}

resource "aws_route_table" "pri_rt" {
  vpc_id = aws_vpc.vpcgoose.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat.id
  }
}

resource "aws_route_table_association" "pri_rt_asso" {
  subnet_id      = aws_subnet.pri_subnet.id
  route_table_id = aws_route_table.pri_rt.id
}

resource "aws_route_table_association" "pri_rt_asso1" {
  subnet_id      = aws_subnet.pri_subnet1.id
  route_table_id = aws_route_table.pri_rt.id
}

resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "keypair" {
  key_name   = "keypair"
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "local_file" "key-content" {
  content  = tls_private_key.rsa.private_key_pem
  filename = "${aws_key_pair.keypair.key_name}.pem"
}

# resource "aws_security_group" "SG" {
#   name        = "SG"
#   description = "Security group"
#   vpc_id      = aws_vpc.vpc.id

#   dynamic "ingress" {
#     for_each = var.SG_inbound_ports_map
#     content {
#       from_port   = ingress.key
#       to_port     = ingress.key
#       protocol    = "tcp"
#       cidr_blocks = ["0.0.0.0/0"]
#       description = ingress.value
#     }
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }

#   tags = {
#     Name = "SG"
#   }
# }

resource "aws_security_group" "ecs_tasks_sg" {
  name        = "ecs-tasks-sg"
  description = "Security group for ECS tasks"
  vpc_id      = aws_vpc.vpcgoose.id


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    security_groups = [aws_security_group.lb_sg.id] 
    # cidr_blocks = ["0.0.0.0/0"]
    description = "ALB ecs app access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ecs-tasks-sg"
  }
}

resource "aws_security_group" "lb_sg" {
  name        = "alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.vpcgoose.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "alb-sg"
  }
}

resource "aws_security_group" "db_sg" {
  name        = "db-sg"
  description = "Security group for db"
  vpc_id      = aws_vpc.vpcgoose.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.ecs_tasks_sg.id]
    # cidr_blocks = ["0.0.0.0/0"]
    description = "PostgreSQL access for app only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }

  tags = {
    Name = "db_sg"
  }
}

# resource "aws_security_group" "ecs_tasks_sg" {
#   name        = "ecs-tasks-sg"
#   description = "Security group for ECS tasks"
#   vpc_id      = aws_vpc.vpcgoose.id

#   # ingress {
#   #   from_port   = 22
#   #   to_port     = 22
#   #   protocol    = "tcp"
#   #   cidr_blocks = ["0.0.0.0/0"] 
#   #   description = "SSH access"
#   # }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"] 
#   }

#   tags = {
#     Name = "ecs_tasks_sg"
#   }
# }

# resource "aws_security_group_rule" "allow_alb_to_ecs_3000" {
#   type                     = "ingress"
#   from_port                = 3000
#   to_port                  = 3000
#   protocol                 = "tcp"
#   security_group_id        = aws_security_group.ecs_tasks_sg.id
#   source_security_group_id = aws_security_group.lb_sg.id
#   description              = "Allow ALB to reach ECS tasks"
# }

# resource "aws_security_group_rule" "allow_alb_to_ecs_80" {
#   type                     = "ingress"
#   from_port                = 80
#   to_port                  = 80
#   protocol                 = "tcp"
#   security_group_id        = aws_security_group.ecs_tasks_sg.id
#   source_security_group_id = aws_security_group.lb_sg.id
#   description              = "Allow ALB health checks"
# }

# resource "aws_security_group" "lb_sg" {
#   name        = "alb_sg"
#   description = "Security group for ALB"
#   vpc_id      = aws_vpc.vpcgoose.id

#   ingress {
#     from_port   = 80
#     to_port     = 80
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"] 
#   }

#   ingress {
#     from_port   = 443
#     to_port     = 443
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]  
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }

#   tags = {
#     Name = "alb-sg"
#   }
# }

# resource "aws_security_group" "db_sg" {
#   name        = "db-sg"
#   description = "Security group for db"
#   vpc_id      = aws_vpc.vpcgoose.id

#   ingress {
#     from_port   = 5432
#     to_port     = 5432
#     protocol    = "tcp"
#     security_groups = [aws_security_group.ecs_tasks_sg.id]
#     description = "Allow ECS tasks to access the database"
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"] 
#   }

#   tags = {
#     Name = "db_sg"
#   }
# }

resource "aws_kms_key" "kms_key" {
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "random_password" "password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "secret" {
  name                    = "secret"
  kms_key_id              = aws_kms_key.kms_key.key_id
  recovery_window_in_days = 0
}

data "aws_secretsmanager_secret" "secret" {
  name = "secret"
  depends_on = [
    aws_secretsmanager_secret.secret
  ]
}

resource "aws_secretsmanager_secret_version" "version" {
  secret_id = aws_secretsmanager_secret.secret.id
  secret_string = jsonencode({
    DB_USER = "pgresql"
    DB_PASS = random_password.password.result
    # docker_username = var.username
    # docker_password = var.password
  })
}

data "aws_secretsmanager_secret_version" "version" {
  secret_id = aws_secretsmanager_secret.secret.id
  depends_on = [
    aws_secretsmanager_secret_version.version
  ]
}

resource "aws_rds_cluster" "aurora_postgresql" {
  cluster_identifier     = "aurora-rds"
  engine                 = "aurora-postgresql"
  engine_version         = "14.6"
  engine_mode            = "provisioned"
  database_name          = "eodsjtAurora"
  master_username        = jsondecode(data.aws_secretsmanager_secret_version.version.secret_string)["DB_USER"]
  master_password        = jsondecode(data.aws_secretsmanager_secret_version.version.secret_string)["DB_PASS"]
  db_subnet_group_name   = aws_db_subnet_group.aurora_postgresql.name
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  serverlessv2_scaling_configuration {
    max_capacity = 1.0
    min_capacity = 0.5
  }
}

resource "aws_rds_cluster_instance" "aurora_postgresql_instance" {
  cluster_identifier  = aws_rds_cluster.aurora_postgresql.id
  instance_class      = "db.serverless" # "db.t3.medium"
  engine              = aws_rds_cluster.aurora_postgresql.engine
  engine_version      = aws_rds_cluster.aurora_postgresql.engine_version
  publicly_accessible = false
}

#### IAM
data "aws_iam_policy_document" "ecs_task_assume_role" {
  version = "2008-10-17"
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ecs_task_assume_role" {
  name               = "ecs_task_assume_role"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json
}

data "aws_iam_policy_document" "ecs_task_policy" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:BatchGetImage",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "cloudfront:ListDistributions",
      "cloudfront:GetDistribution",
      "cloudwatch:PutMetricData",
      "cloudwatch:ListMetrics",
      "ecs:DescribeTasks",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:DescribeContainerInstances",
      "ecs:StopTask",
      "ecs:RunTask",
      "ecs:UpdateService",
      "kms:Decrypt",
      "s3:GetObject",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetHealth",
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:AssignPrivateIpAddresses",
      "ec2:UnassignPrivateIpAddresses"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ecs_task_policy" {
  name   = "ecs-task-policy"
  policy = data.aws_iam_policy_document.ecs_task_policy.json
}

resource "aws_iam_role_policy_attachment" "ecs_task_exe_attach" {
  role       = aws_iam_role.ecs_task_assume_role.name
  policy_arn = aws_iam_policy.ecs_task_policy.arn
}

#####
resource "aws_iam_policy" "iam_fargate_role_policy" {
  name = "FargateRolePolicy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "iam:PassRole",
        Resource = [
          aws_iam_role.ecs_task_assume_role.arn,
          aws_iam_role.exe_role_containeragentdocker_policy.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "pass_role_attachment" {
  role       = aws_iam_role.pass_exe_role.name
  policy_arn = aws_iam_policy.iam_fargate_role_policy.arn
}

data "aws_iam_policy_document" "ecs_pass_exe_assume_role" {
  version = "2008-10-17"
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "pass_exe_role" {
  name               = "pass_exe_role"
  assume_role_policy = data.aws_iam_policy_document.ecs_pass_exe_assume_role.json
}

##
data "aws_iam_policy_document" "exe_role_containeragentdocker" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "ecs:DescribeTasks",
      "ecs:StartTask",
      "ecs:StopTask",
      "ecs:UpdateService",
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "logs:*",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "cloudwatch:PutMetricData",
      "cloudwatch:ListMetrics",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetHealth"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "exe_role_containeragentdocker_policy" {
  name   = "exe_role_containeragentdocker_policy"
  policy = data.aws_iam_policy_document.exe_role_containeragentdocker.json
}

resource "aws_iam_role" "exe_role_containeragentdocker_policy" {
  name               = "exe_role_containeragentdocker_policy"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json
}

resource "aws_iam_role_policy_attachment" "exe_role_containeragentdocker_policy" {
  role       = aws_iam_role.exe_role_containeragentdocker_policy.name
  policy_arn = aws_iam_policy.exe_role_containeragentdocker_policy.arn
}

data "aws_iam_policy_document" "secret_policy" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "ssm:GetParameter",
      "kms:Decrypt",
      "rds-db:connect",
      "rds:DescribeDBInstances",
      "secretsmanager:GetSecretValue"
    ]
    resources = [data.aws_secretsmanager_secret.secret.arn]
  }
}

resource "aws_iam_policy" "secret_policy" {
  name   = "secretmanager"
  policy = data.aws_iam_policy_document.secret_policy.json
}

resource "aws_iam_role_policy_attachment" "exe-kms-secret-rds-attach" {
  role       = aws_iam_role.exe_role_containeragentdocker_policy.name
  policy_arn = aws_iam_policy.secret_policy.arn
}

resource "aws_iam_role_policy_attachment" "task-kms_secret_rds_attach" {
  role       = aws_iam_role.ecs_task_assume_role.name
  policy_arn = aws_iam_policy.secret_policy.arn
}

# resource "aws_iam_instance_profile" "instance-profile" {
#   name = "instance-profile"
#   role = aws_iam_role.exe_role_containeragentdocker_policy.name
# }

data "aws_iam_policy_document" "s3" {
  statement {
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "kms:Decrypt"
    ]
    resources = [
      "arn:aws:s3:::sjteod-buckett",
      "arn:aws:s3:::sjteod-buckett/*",
      "${aws_s3_bucket.srseod-bucket.arn}/*"
    ]
  }
  statement {
    sid    = "DenyDeleteTerraformState"
    effect = "Deny"

    actions = [
      "s3:DeleteObject",
    ]

    resources = [
      "arn:aws:s3:::sjteod-buckett",
      "arn:aws:s3:::sjteod-buckett/*",
    ]
  }
}

resource "aws_iam_policy" "s3" {
  name   = "s3"
  policy = data.aws_iam_policy_document.s3.json
}

resource "aws_iam_role_policy_attachment" "exe_s3_attach" {
  role       = aws_iam_role.exe_role_containeragentdocker_policy.name
  policy_arn = aws_iam_policy.s3.arn
}

resource "aws_iam_role_policy_attachment" "task_s3_attach" {
  role       = aws_iam_role.ecs_task_assume_role.name
  policy_arn = aws_iam_policy.s3.arn
}

data "aws_iam_policy_document" "cloudfront_policy" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = [
      "cloudfront:ListDistributions",
      "cloudfront:GetDistribution",
      "cloudfront:CreateInvalidation"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "cloudfront_policy" {
  name   = "cloudfront-policy"
  policy = data.aws_iam_policy_document.cloudfront_policy.json
}

resource "aws_iam_role_policy_attachment" "exe_cloudfront_attach" {
  role       = aws_iam_role.exe_role_containeragentdocker_policy.name
  policy_arn = aws_iam_policy.cloudfront_policy.arn
}

resource "aws_iam_role_policy_attachment" "task_cloudfront_attach" {
  role       = aws_iam_role.ecs_task_assume_role.name
  policy_arn = aws_iam_policy.cloudfront_policy.arn
}

resource "aws_acm_certificate" "cert" {
  domain_name       = "thinkeod.com"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}


#### DNS Validation BALANCER
data "aws_route53_zone" "zone" {
  name         = "thinkeod.com"
  private_zone = false
}

resource "aws_route53_record" "route53_record" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = data.aws_route53_zone.zone.name
  type    = "A"

  alias {
    name                   = aws_alb.lb.dns_name
    zone_id                = aws_alb.lb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "acm_record" {
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.zone.zone_id
}

resource "aws_acm_certificate_validation" "validation" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [for record in aws_route53_record.acm_record : record.fqdn]
}

resource "aws_alb" "lb" {
  name               = "lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = [aws_subnet.pub_subnet.id, aws_subnet.pub_subnet1.id]
  # subnets = local.subnets

  # access_logs {
  # bucket  = aws_s3_bucket.s3.id
  #   prefix  = "test-lb"
  #   enabled = true
  # }

  tags = {
    Environment = "alb"
  }
}

resource "aws_alb_target_group" "target" {
  name        = "target"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.vpcgoose.id

  health_check {
    enabled             = true
    healthy_threshold   = 3
    interval            = 30
    path                = "/health"
    timeout             = 10
    unhealthy_threshold = 5
    matcher             = "200,301,302"
  }
}

resource "aws_alb_listener" "lb_listener" {
  load_balancer_arn = aws_alb.lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_alb_listener" "https_listener" {
  load_balancer_arn = aws_alb.lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.target.arn
  }
}

#### ECS
resource "aws_ecs_cluster" "ecs" {
  name = "ecs"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "task_def" {
  family                   = "nodejs"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.exe_role_containeragentdocker_policy.arn
  task_role_arn            = aws_iam_role.ecs_task_assume_role.arn
  cpu                      = 1024
  memory                   = 2048
  network_mode             = "awsvpc"
  container_definitions = jsonencode([
    {
      name   = "nodejs_image"
      image  = "docker.io/eodgeorge/sjtnodejs:goosev1"
      cpu    = 512
      memory = 1024
      # repositoryCredentials = {
      #   credentialsParameter = aws_secretsmanager_secret.secret.arn
      # }
      essential = true
      environment = [
        for key, value in local.environment : {
          name  = key
          value = value
        }
      ]

      logConfiguration = {
        logDriver = "awslogs", ##fluentd, splunk

        options = {
          awslogs-group         = aws_cloudwatch_log_group.MyAppLogs.name,
          awslogs-region        = local.region
          awslogs-stream-prefix = "ecs"
        }
      }

      portMappings = [
        {
          containerPort = 3000
          "protocol" : "tcp"
        }
      ]
    },
#     {
#       name      = "fluent_bit"
#       image     = "fluent/fluent-bit:latest"
#       cpu       = 128
#       memory    = 256
#       essential = true
#       command   = ["/fluent-bit/bin/fluent-bit"]
#       args      = ["-c", "/fluent-bit/etc/fluent-bit.conf", "-v"]
#        mountPoints = [
#         {
#           "sourceVolume": "app-logs",
#           "containerPath": "/var/log"
#         },
#         {
#           sourceVolume  = "config-volume",
#           containerPath = "/fluent-bit/etc"
#         }
#       ]
#       logConfiguration = {
#         logDriver = "awslogs"
#         options = {
#           awslogs-group         = aws_cloudwatch_log_group.MyAppLogs.name
#           awslogs-region        = local.region
#           awslogs-stream-prefix = "ecs-fluentbit"
#         }
#       }
#       dependsOn = [
#         {
#           containerName = "init-container",
#           condition     = "SUCCESS"
#         }
#       ]
#     },
    {
      name      = "init-container"
      image     = "amazonlinux"
      cpu       = 128
      memory    = 256
      essential = false
      command   = ["sh", "-c", "yum install -y yum-utils && yum update -y && yum install -y aws-cli && aws s3 cp s3://${aws_s3_bucket.srseod-bucket.bucket}/${aws_s3_object.fluentbit-conf.key} /config/fluent-bit.conf && tail -f /dev/null"]
      mountPoints = [
        {
          sourceVolume  = "config-volume",
          containerPath = "/config"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.MyAppLogs.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "ecs-init-container"
        }
      }
    }
  ])

  volume {
    name = "config-volume"
  }
}

resource "aws_ecs_service" "service" {
  name        = "nodejs-service"
  launch_type = "FARGATE"
  cluster     = aws_ecs_cluster.ecs.id
  # scheduling_strategy                = "REPLICA"
  task_definition                    = aws_ecs_task_definition.task_def.arn
  desired_count                      = 2
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
  depends_on = [aws_iam_role_policy_attachment.ecs_task_exe_attach,
    aws_alb_listener.lb_listener,
    aws_alb_target_group.target,
    aws_rds_cluster.aurora_postgresql
  ]

  network_configuration {
    security_groups = [aws_security_group.ecs_tasks_sg.id] #aws_security_group.lb_sg.id
    # subnets          = local.pri-subnets
    subnets          = [aws_subnet.pri_subnet.id, aws_subnet.pri_subnet1.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_alb_target_group.target.arn
    container_name   = "nodejs_image"
    container_port   = 3000
  }
}

resource "aws_cloudwatch_log_group" "MyAppLogs" {
  name = "/ecs/${local.name}/MyAppLogs"
}

resource "aws_cloudwatch_metric_alarm" "high_cpu_alarm" {
  alarm_name          = "high-cpu-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = "80" # CPU > 80%
  alarm_description   = "Alarm when CPU exceeds 80%"

  dimensions = {
    ClusterName = aws_ecs_cluster.ecs.name
    ServiceName = aws_ecs_service.service.name
  }

  # alarm_actions = [aws_sns_topic.auto_scaling_alarm_topic.arn]
}

resource "aws_cloudwatch_metric_alarm" "high_memory_alarm" {
  alarm_name          = "high-memory-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = "80" # Memory > 80%
  alarm_description   = "Alarm when Memory exceeds 80%"

  dimensions = {
    ClusterName = aws_ecs_cluster.ecs.name
    ServiceName = aws_ecs_service.service.name
  }

  # alarm_actions = [aws_sns_topic.auto_scaling_alarm_topic.arn]
}

#############
resource "aws_appautoscaling_target" "ecs_target" {
  max_capacity       = 4
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.ecs.name}/${aws_ecs_service.service.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
  depends_on         = [aws_ecs_service.service]
}

resource "aws_appautoscaling_policy" "scale_out" {
  name               = "scale-out-policy"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  policy_type        = "TargetTrackingScaling"
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace
  depends_on         = [aws_ecs_service.service]

  target_tracking_scaling_policy_configuration {
    target_value = 50.0
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_in_cooldown  = 300
    scale_out_cooldown = 300
  }
}

resource "aws_appautoscaling_policy" "scale_in" {
  name               = "scale-in-policy"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  policy_type        = "TargetTrackingScaling"
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace
  depends_on         = [aws_ecs_service.service]

  target_tracking_scaling_policy_configuration {
    target_value = 50.0
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_in_cooldown  = 300
    scale_out_cooldown = 300
  }
}
