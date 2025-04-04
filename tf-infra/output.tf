output "lb-id" {
  value = aws_alb.lb.id
}

output "lb-dns" {
  value = aws_alb.lb.dns_name
}

output "db-endpiont" {
  value = aws_rds_cluster.aurora_postgresql.endpoint
}

output "db-name" {
  value = aws_rds_cluster.aurora_postgresql.database_name
}

# output "env" {
#   value = local.environment
# }

output "s3_url" {
  value = aws_s3_bucket_website_configuration.srseod-bucket-web.website_endpoint
}