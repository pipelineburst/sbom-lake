from aws_cdk import (
    Duration,
    Stack,
    aws_iam as iam,
    aws_s3 as s3,
    aws_kms as kms,
    custom_resources as cr,
    RemovalPolicy,
)
from constructs import Construct

class SbomLakeStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # KMS key for our S3 bucket 

        key = kms.Key(self, "SbomLakeKey",
            key_spec=kms.KeySpec.SYMMETRIC_DEFAULT,
            key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
            alias="SbomLakeKey"
        )
        
        # KMS Key policy for inspector sbom export permissions to access key for S3 bucket
        add_key_policy = key.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["kms:Decrypt","kms:GenerateDataKey"],
                resources=["*"],
                principals=[iam.ServicePrincipal("inspector2.amazonaws.com")],
                conditions={
                    "ArnLike": {
                            "aws:SourceArn": "arn:aws:inspector2:"
                            + "eu-west-1"
                            + ":"
                            + "069127586842"
                            + ":report/*"
                        },
                    "StringEquals": {
                            "aws:SourceAccount": "069127586842"
                        }
                    },
                )
        )

        ### Create Sbom S3 bucket
        bucket = s3.Bucket(self, "SbomLake",
            bucket_name="sbom-lake-u4jedu3",
            auto_delete_objects=True,
            versioned=True,
            bucket_key_enabled=True,
            removal_policy=RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=key,
            intelligent_tiering_configurations=[
                s3.IntelligentTieringConfiguration(
                name="my_s3_tiering",
                archive_access_tier_time=Duration.days(90),
                deep_archive_access_tier_time=Duration.days(180),
                prefix="prefix",
                tags=[s3.Tag(
                    key="key",
                    value="value"
                )]
             )],      
            lifecycle_rules=[
                s3.LifecycleRule(
                    noncurrent_version_expiration=Duration.days(7)
                )
            ],
        )
        
        ### Create S3 bucket policy for inspector sbom export permissions
        add_s3_policy = bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject","s3:PutObject","s3:AbortMultipartUpload"],
                resources=[bucket.arn_for_objects("*")],
                principals=[iam.ServicePrincipal("inspector2.amazonaws.com")],
                conditions={
                    "ArnLike": {
                            "aws:SourceArn": "arn:aws:inspector2:"
                            + "eu-west-1"
                            + ":"
                            + "069127586842"
                            + ":report/*"
                        },
                    "StringEquals": {
                            "aws:SourceAccount": "069127586842"
                        }
                    },
                )
            )
    