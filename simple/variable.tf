variable "SG_inbound_ports_map" {
  description = "Map of ports and their descriptions for the security group ingress rules"
  type        = map(string)
  default = {
    22   = "ssh access"
    80   = "http"
    443  = "https"
    3000 = "app"
    5432 = "postgressql"
    8125 = "statsD"
  }
}

locals {
  subnets = [
    aws_subnet.pub_subnet.id,
    aws_subnet.pub_subnet1.id
  ]

  pri-subnets = [
    aws_subnet.pri_subnet.id,
    aws_subnet.pri_subnet1.id
  ]

  name   = "nodejs"
  region = "eu-west-2"

  environment = {
    "DB_PASS" = jsondecode(data.aws_secretsmanager_secret_version.version.secret_string)["DB_PASS"]
    "DB_USER" = jsondecode(data.aws_secretsmanager_secret_version.version.secret_string)["DB_USER"]
    "DB_HOST" = "${aws_rds_cluster.aurora_postgresql.endpoint}"
    "DB_NAME" = "${aws_rds_cluster.aurora_postgresql.database_name}"
    "DB_PORT" = "5432"
  }
}

variable "username" {
  default = "eodgeorge"
}

variable "password" {
  default = "Wenger12345@"
}


variable "name" {
  default = "ecs-sjtgoose"
}



# environment = [
#   {
#     "name" : "DB_PASS",
#     "value" : jsondecode(data.aws_secretsmanager_secret_version.version.secret_string)["DB_PASS"]
#   },
#   {
#     "name" : "DB_USER",
#     "value" : jsondecode(data.aws_secretsmanager_secret_version.version.secret_string)["DB_USER"]
#   },
#   {
#     "name" : "DB_HOST",
#     "value" : "${aws_rds_cluster.aurora_postgresql.endpoint}"
#   },
#   {
#     "name" : "DB_NAME",
#     "value" : "${aws_rds_cluster.aurora_postgresql.database_name}"
#   },
#   {
#     "name" : "DB_PORT",
#     "value" : "5432"
#   }
# ]



# resource "aws_security_group" "SG" {
#   name        = "ecs-tasks-sg"
#   description = "Security group for ECS tasks"
#   vpc_id      = aws_vpc.vpc.id


#   ingress {
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"] 
#     description = "SSH access"
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"] 
#   }

#   tags = {
#     Name = "ecs-tasks-sg"
#   }
# }

# resource "aws_security_group" "lb_sg" {
#   name        = "alb-sg"
#   description = "Security group for ALB"
#   vpc_id      = aws_vpc.vpc.id

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
#   from_port   = 0
#   to_port     = 0
#   protocol    = "-1"
#   cidr_blocks = ["0.0.0.0/0"]
# }

#   tags = {
#     Name = "alb-sg"
#   }
# }

# resource "aws_security_group" "db_sg" {
#   name        = "db-sg"
#   description = "Security group for db"
#   vpc_id      = aws_vpc.vpc.id

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

# resource "aws_security_group_rule" "allow_SG_to_db" {
#   type                     = "ingress"
#   from_port                = 5432
#   to_port                  = 5432
#   protocol                 = "tcp"
#   security_group_id        = aws_security_group.db_sg.id
#   source_security_group_id = aws_security_group.SG.id
# }

# resource "aws_security_group_rule" "allow_ALB_to_SG" {
#   type                     = "ingress"
#   from_port                = 3000
#   to_port                  = 3000
#   protocol                 = "tcp"
#   security_group_id        = aws_security_group.SG.id
#   source_security_group_id = aws_security_group.lb_sg.id
# }