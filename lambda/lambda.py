import json
import boto3
from time import sleep

client = boto3.client('inspector2')

def lambda_handler(event, context):
    repo_name_in = event["detail"]["repository-name"]
    repo_name = repo_name_in.split("repository/")[-1]
    image_tag = event['detail']['image-tags'][0]
    bucket_name = "sbom-lake-u4jedu3"
    kms_key_arn = "arn:aws:kms:eu-west-1:069127586842:key/f70a8a11-2181-478d-9798-fbfe9e52870a"
    print(repo_name)
    print(image_tag)

    while True:
        try:
            response = client.list_coverage(
                    filterCriteria={
                        'ecrRepositoryName': [
                            {
                                'comparison': 'EQUALS',
                                'value': repo_name
                            }
                        ],
                        'ecrImageTags': [
                            {
                            'comparison': 'EQUALS',
                            'value': image_tag
                            }
                        ]
                    },
            )
        except Exception as e:
            print('retrying list-coverage call...')
            sleep(5)
            continue
        print(response['coveredResources'][0]['scanStatus']['reason'])
        break

    if response['coveredResources'][0]['scanStatus']['reason'] == "SUCCESSFUL" and response['coveredResources'][0]['scanStatus']['statusCode'] == "ACTIVE" and repo_name != "eaa/eaa-cicd-probe":
        print('all good, the image is eligable for sbom export and its not a CICD probe...')

        while True:
            try:
                print("trying to submit sbom export request for:")
                print(repo_name)
                print(image_tag)
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
                            'value': image_tag
                            }
                        ]
                    },
                    s3Destination={
                        'bucketName': bucket_name,
                        'kmsKeyArn': kms_key_arn
                    }
                )
            except Exception as e:
                print('retrying...')
                sleep(5)
                continue
            break
        print("All done... happy days")
        return {
            'statusCode': 200,
            'body': json.dumps(response)
        }
    else:
        print("Not proceeding, the image is not eligible for sbom export")