"""
Ansible helpers
"""

import boto3
import botocore


class AnsibleAWSClient:
    def __init__(self, module):
        self.module = module
        self.session = self.client()

    def client(self):
        module = self.module
        access_key = module.params.get("aws_access_key")
        secret_key = module.params.get("aws_secret_key")
        security_token = module.params.get("security_token")

        try:
            return boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=security_token,
            )
        except (
            botocore.exceptions.ClientError,
            botocore.exceptions.BotoCoreError,
        ) as e:
            module.fail_json_aws(e, msg="Failed to connect to AWS")


def fail_json(module, result, exception, msg=None):
    result["failed"] = True
    if msg:
        result["msg"] = "{}: {}".format(msg, exception)
    else:
        result["msg"] = "{}".format(str(exception))
    module.exit_json(**result)
