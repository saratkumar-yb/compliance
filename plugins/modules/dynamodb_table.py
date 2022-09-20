#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, <Name> <main> // Todo
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: check_remediate_compliance
short_description: This is simply for a check to see if the tables are compliant
version_added: "0.0.1"
description: This is simply for a check to see if the tables are compliant in current account. WILL ***NOT*** MODIFY ANY DynamoDB TABLES IN AWS.
options:
    aws_access_key:
        description:
        - AWS Access Key
        type: str
        required: True
    aws_secret_key:
        description:
        - AWS Secret Key
        type: str
        required: True
    security_token:
        description:
        - AWS Security Token
        type: str
        required: True
    table_name:
        description:
        - Dynamo DB table name
        type: str
        required: True
    region:
        description:
        - AWS Region
        type: str
        required: True
    point_in_time_value:
        description:
        - Check and remediate point in time compliance
        type: bool
        required: False
    auto_scaling_value:
        description:
        - Check and remediate auto scaling compliance
        type: bool
        required: False
author:
    - Name (@SKanjarla_a)
"""

EXAMPLES = r"""
- name: Check Remediate Compliance
  compliance.dynamodb.check_remediate_compliance:
    aws_access_key: "{{ aws_access_key }}"
    aws_secret_key: "{{ aws_secret_key }}"
    security_token: "{{ aws_security_token }}"
    region: "us-east-2"
    table_name: "test"
    point_in_time_value: true
    auto_scaling_value: false
  register: result
- debug:
    msg: "{{ result.tables_map }}"
"""

RETURN = r"""
## TO-DO
"""
import botocore
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.compliance.dynamodb.plugins.module_utils.helpers import (
    AnsibleAWSClient,
    fail_json,
)
from ansible_collections.compliance.dynamodb.plugins.module_utils.remediation_functions import (
    detect_auto_scaling_compliance,
    detect_point_in_time_compliance,
    remediate_point_in_time,
    remediate_auto_scaling,
    remove_auto_scaling,
)


def check_remediate_compliance():
    """
    THIS ***WILL*** MODIFY ANY DynamoDB TABLES IN AWS
    This will check and remediate all the tables which are non compliant in current account
    """
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        aws_access_key=dict(
            type="str",
            required=True,
            fallback=(env_fallback, ["AWS_ACCESS_KEY_ID"]),
            no_log=True,
        ),
        aws_secret_key=dict(
            type="str",
            required=True,
            fallback=(env_fallback, ["AWS_SECRET_ACCESS_KEY"]),
            no_log=True,
        ),
        security_token=dict(
            aliases=[
                "access_token",
                "aws_security_token",
                "session_token",
                "aws_session_token",
            ],
            fallback=(env_fallback, ["AWS_SESSION_TOKEN"]),
            no_log=True,
        ),
        table_name=dict(
            type="str",
            required=True,
        ),
        region=dict(
            type="str",
            required=True,
        ),
        point_in_time_value=dict(
            type="bool",
            required=False,
        ),
        auto_scaling_value=dict(
            type="bool",
            required=False,
        ),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
        ansible_facts={},
    )

    table_name = module.params.get("table_name")
    region = module.params.get("region")
    pit_check_value = module.params.get("point_in_time_value", None)
    as_check_value = module.params.get("auto_scaling_value", None)

    # if not pit_check and not as_check:
    #     fail_json(module, result, None, msg="Both point_in_time_value and auto_scaling_value cannot be false")

    client = AnsibleAWSClient(module)

    # tables_map is a list of tables with its respective region,
    # point_in_time_compliant, auto_scaling_compliant, & state
    tables_map = []

    try:
        # Check for point in time compliance or auto scaling compliance
        # depending upon the params, by default both as and pit are checked
        # Add table related data ot tables_map
        table = {}

        # Preparing tables_map list for output
        table["name"] = table_name
        table["region"] = region
        # check if pit_check_value and as_check_value is not None
        # If not None detect current pit and as states
        if not isinstance(pit_check_value, type(None)):
            table["point_in_time_compliance"] = detect_point_in_time_compliance(
                client, region, table_name
            )
        if not isinstance(as_check_value, type(None)):
            table["auto_scaling_compliance"] = detect_auto_scaling_compliance(
                client, region, table_name
            )
        tables_map.append(table)
    except Exception as e:
        fail_json(module, result, e)

    result["tables"] = tables_map

    # Loop through all the tables
    for table_map in tables_map:
        table_name = table_map.get("name")
        region = table_map.get("region")

        try:
            table_map["state"] = "ok"
            # check if pit_check_value is not None
            # if not None; check if current state is matching with required state
            # if required state is differnt set the state
            if not isinstance(pit_check_value, type(None)):
                current_pit_compliance = table_map.get("point_in_time_compliance")
                if pit_check_value != current_pit_compliance:
                    if not module.check_mode:
                        remediate_point_in_time(
                            client, region, table_name, state=pit_check_value
                        )
                        table_map[
                            "point_in_time_compliance"
                        ] = detect_point_in_time_compliance(client, region, table_name)
                    result["changed"] = True
                    table_map["state"] = "changed"
            # check if as_check_value is not None
            # if not None; check if current state is matching with required state
            # if required state is differnt set the state
            if not isinstance(as_check_value, type(None)):
                current_as_compliance = table_map.get("auto_scaling_compliance")
                if as_check_value != current_as_compliance:
                    if not module.check_mode:
                        if as_check_value == True:
                            remediate_auto_scaling(client, region, table_name)
                            table_map[
                                "auto_scaling_compliance"
                            ] = detect_auto_scaling_compliance(
                                client, region, table_name
                            )
                        elif as_check_value == False:
                            remove_auto_scaling(client, region, table_name)
                            table_map[
                                "auto_scaling_compliance"
                            ] = detect_auto_scaling_compliance(
                                client, region, table_name
                            )
                    result["changed"] = True
                    table_map["state"] = "changed"

        except Exception as e:
            fail_json(module, result, e)

    module.exit_json(**result)


def main():
    check_remediate_compliance()


if __name__ == "__main__":
    main()
