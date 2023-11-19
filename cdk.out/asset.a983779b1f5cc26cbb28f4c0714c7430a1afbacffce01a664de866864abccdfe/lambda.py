import json
import boto3

client = boto3.client('inspector2')

def lambda_handler(event, context):
    while True:
        try:
            response = client.create_sbom_export(
                reportFormat='SPDX_2_3',
                resourceFilterCriteria={
                    'ecrRepositoryName': [
                        {
                            'comparison': 'EQUALS',
                            'value': event['detail']['repository-name']
                        }
                    ],
                    'ecrImageTags': [
                        {
                        'comparison': 'EQUALS',
                        'value': event['detail']['image-tag']
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
            from time import sleep
            sleep(5)
            continue

        return {
            'statusCode': 200,
            'body': json.dumps(response)
        }
        break
