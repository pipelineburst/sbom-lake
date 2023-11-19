from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    aws_events as events,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_events_targets as event_targets
)

class SbomLambdaStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Defines an AWS Lambda function
        my_lambda = _lambda.Function(
            self, 'SbomExportHandler',
            runtime=_lambda.Runtime.PYTHON_3_11,
            code=_lambda.Code.from_asset('lambda'),
            handler='lambda.lambda_handler',
            timeout=Duration.seconds(900)
        )

        # Defines an EventBridge Target, which also adds the trigger to the Lambda Function
        my_target = event_targets.LambdaFunction(
            handler=my_lambda
        )

        # Defines EventBridge Rule
        rule = events.Rule(self, "eventbridge_sbom_inspector2_rule",
            event_pattern=events.EventPattern(
                source=["aws.inspector2"],
                detail_type=["Inspector2 Scan"],
                detail={
                    "scan-status": ["INITIAL_SCAN_COMPLETE"],
                    }
                ),
            targets=[my_target]
        )

        # Adding the inspector permissions to the Lambda execution role
        add_execution_policy = my_lambda.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["inspector2:*"],
                resources=["*"],
                )
        )