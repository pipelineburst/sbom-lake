import json
import boto3
from time import sleep

client = boto3.client('inspector2')

def lambda_handler(event, context):
    while True:
        try:
            txt = event['detail']['repository-name']
            repo_name = txt.split(":")[-1]
            print(repo_name)
            response = client.create_sbom_export(
                reportFormat='SPDX_2_3',
                resourceFilterCriteria={
                    'ecrRepositoryName': [
                        {
                            'comparison': 'EQUALS',
                            'value': repo_name
                        }
                    ],
                    'ecrImageTags': [
                        {
                        'comparison': 'EQUALS',
                        'value': event['detail']['image-tags'][0]
                        }
                    ]
                },
                s3Destination={
                    'bucketName': 'sbom-lake-u4jedu3',
                    'kmsKeyArn': 'arn:aws:kms:eu-west-1:069127586842:key/f70a8a11-2181-478d-9798-fbfe9e52870a'
                }
            )
        except Exception as e:
            print('retrying...')
            sleep(5)
            continue

        return {
            'statusCode': 200,
            'body': json.dumps(response)
        }
        break
