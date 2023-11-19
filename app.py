#!/usr/bin/env python3
import aws_cdk as cdk

from stacks.sbom_lake_stack import SbomLakeStack
from stacks.lambda_stack import SbomLambdaStack


app = cdk.App()

SbomLakeStack(app, "SbomLakeStack",
            description="Provision Sbom Lake resources", 
            termination_protection=False, 
            tags={"project":"sbomLake"}, 
            env=cdk.Environment(region="eu-west-1"),
)

SbomLambdaStack(app, "SbomLambdaStack",
            description="Provision the Lambda resources", 
            termination_protection=False, 
            tags={"project":"sbomLake"}, 
            env=cdk.Environment(region="eu-west-1"),
)
            
app.synth()