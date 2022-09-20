import datetime
import os

default_role_name = "appAwsEngineers"
default_region = "us-east-1"


def remediate_point_in_time(client, region_name, table_name, state=True):
    """Update point-in-time recover for dynamoDB

    Parameters
    ----------
    table_name : str
        The name of the table to remediate point in time non-compliance
    PointInTimeRecoveryEnabled: bool
        Whether to enable or disable point in time recovery

    Returns
    -------
    bool
        True if point in time is now enabled,
        False otherwise
    """

    dynamo_client = client.session.client("dynamodb", region_name=region_name)

    # try:
    # Enable compliance through the boto3 dynamodb client
    response = dynamo_client.update_continuous_backups(
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": state},
    )
    return (
        response["ContinuousBackupsDescription"]["ContinuousBackupsStatus"] == "ENABLED"
    )

def remove_auto_scaling(client, region_name, table_name):
    application_scaling_client = client.session.client('application-autoscaling', region_name = region_name)

    response_write = application_scaling_client.deregister_scalable_target(
        ServiceNamespace = 'dynamodb',
        ResourceId = "table/{}".format(table_name),
        ScalableDimension = 'dynamodb:table:WriteCapacityUnits'
    )
    response_read = application_scaling_client.deregister_scalable_target(
        ServiceNamespace = 'dynamodb',
        ResourceId = "table/{}".format(table_name),
        ScalableDimension = 'dynamodb:table:ReadCapacityUnits'
    )
    return response_read, response_write

def get_scaling_bounds(client, region_name, table_name, scalable_dimension):
    """Get scaling bounds for a dynamoDB table

    This will get the upper and lower scaling bounds of a dynamoDB table given its name and the scaling dimension
    to use.

    For instance, scaling_attribute.READ_TABLE will get the upper and lowing scaling bounds for the read attribute of that table.
    scaling_attribute.WRITE_TABLE will get the upper and lower scaling bounds for the write attribute of the table

    This does not support scaling attributes for table indices yet.

    Parameters
    ----------
    table_name : str
        The name of the table to get the scaling bounds for
    scalable_dimension: scaling_attribute (str)
        What dimension to utilize for the lower and upper bounds. (READ/WRITE)

    Returns
    -------
    tuple(int, int)
        The upper and lower bounds for table capacity, given the scalable dimension selected
    """

    dynamo_client = client.session.client("dynamodb", region_name=region_name)
    application_scaling_client = client.session.client(
        "application-autoscaling", region_name=region_name
    )

    # This method only supports READ_TABLE and WRITE_TABLE for now
    if scalable_dimension not in ["READ", "WRITE"]:
        raise ValueError("Error, invalid scaling attribute given")

    response = dynamo_client.describe_table(TableName=table_name)

    # Get the current capacity for the table, either read or write.
    if scalable_dimension == "READ":
        current_capacity = response["Table"]["ProvisionedThroughput"][
            "ReadCapacityUnits"
        ]
    else:  # scalable_dimension == scaling_attribute.WRITE_TABLE:
        current_capacity = response["Table"]["ProvisionedThroughput"][
            "WriteCapacityUnits"
        ]

    # if current_capacity == 0: # Only true if it is a PAY_PER_REQUEST table.
    #     return (0, 0)

    aws_dimension = {
        "READ": "dynamodb:table:ReadCapacityUnits",
        "WRITE": "dynamodb:table:WriteCapacityUnits",
    }

    try:

        # Get the upper and lower bound given the scaling attribute selected
        response_read = application_scaling_client.describe_scalable_targets(
            ServiceNamespace="dynamodb",
            ResourceIds=["table/{}".format(table_name)],
            ScalableDimension=aws_dimension[scalable_dimension],
        )

        min_capacity = response_read["ScalableTargets"][0]["MinCapacity"]
        max_capacity = response_read["ScalableTargets"][0]["MaxCapacity"]
        return (min_capacity, max_capacity)
    except:
        # If there is no max or min, then the current capacity is both the upper and lower bounds.
        return (current_capacity, current_capacity)


def apply_auto_scaling(
    client,
    region_name,
    table_name,
    scalable_dimension,
    lower_bound_multiplier=10,
    scale_in_cooldown=60,
    scale_out_cooldown=60,
    target_value=70,
    run_verify=False,
):
    """Apply Auto Scaling for a DynamoDB table


    Parameters
    ----------
    table_name : str
        The name of the table to apply the scaling attributes to
    scalable_dimension: scaling_attribute (ENUM)
        What dimension to utilize for the lower and upper bounds. (READ/WRITE)
    lower_bound_multiplier : int
        How many times greater the upper bound will be set than the lower bound
    scale_in_cooldown: int (> 0)
        Seconds until the table reduces capacity again after already reducing
    scale_out_cooldown: int (> 0)
        Seconds until the table increases capacity again after already increasing
    target_value: int (> 0 and < 100)
        Percent usage of the provisioned throughput that will trigger an auto-scale
    run_verify: bool
        If true, this will return the results of the table modification to check if
        the function ran as intended, and what the values were set to.

    Returns
    -------
    dict
        If run_verify is true, this will return the results of the describe_scalable_targets
        api call after the modification to the table.

        Otherwise, it will return an empty dict
    """

    application_scaling_client = client.session.client(
        "application-autoscaling", region_name=region_name
    )

    # Describes the table scaling properties given the table name and whether the scaling
    # applies to the read attribute or the write attribute
    def describe_scalable_targets(table_name, read_or_write):
        return application_scaling_client.describe_scalable_targets(
            ServiceNamespace="dynamodb",
            ResourceIds=[
                "table/{0}".format(table_name),
            ],
            ScalableDimension="dynamodb:table:{0}CapacityUnits".format(read_or_write),
        )

    # Map the scaling attribute to a string to substitute in for the API calls
    scaling_type = {"READ": "Read", "WRITE": "Write"}
    read_or_write = scaling_type[scalable_dimension]

    lower_bound, upper_bound = get_scaling_bounds(
        client, region_name, table_name, scalable_dimension
    )

    if lower_bound < upper_bound:
        # Auto scaling is already enabled for this particular attribute (READ/WRITE)
        # Do not bother to attempt to remediate it.
        if run_verify:
            describe_scalable_targets(table_name, read_or_write)
        else:
            return {}

    # Set the upper bound to a multiple of the lower bound.
    upper_bound = lower_bound * lower_bound_multiplier

    # Options for the ScalableDimension parameter in the register_scalable_target call
    # 'dynamodb:table:ReadCapacityUnits'|'dynamodb:table:WriteCapacityUnits'|'dynamodb:index:ReadCapacityUnits'|'dynamodb:index:WriteCapacityUnits',

    # Set lower and upper bound for scaling
    application_scaling_client.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId="table/{0}".format(table_name),
        ScalableDimension="dynamodb:table:{0}CapacityUnits".format(read_or_write),
        MinCapacity=lower_bound,
        MaxCapacity=upper_bound,
    )

    # Set when the table should scale up or down
    application_scaling_client.put_scaling_policy(
        PolicyName="FHLBC DynamoDB BSC Basic Scaling Policy",
        ServiceNamespace="dynamodb",
        ResourceId="table/{0}".format(table_name),
        ScalableDimension="dynamodb:table:{0}CapacityUnits".format(read_or_write),
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "PredefinedMetricSpecification": {
                "PredefinedMetricType": "DynamoDB{0}CapacityUtilization".format(
                    read_or_write
                )
            },
            "ScaleOutCooldown": scale_in_cooldown,
            "ScaleInCooldown": scale_out_cooldown,
            "TargetValue": target_value,
        },
    )

    # Check if we should verify the run before returning
    if run_verify:
        return describe_scalable_targets(table_name, read_or_write)
    else:
        return {}


def remediate_auto_scaling(client, region_name, table_name, **params):
    """Remediate Auto Scaling for a DynamoDB table

    This is the main wrapper method for remediating auto scaling. This will handle collection of
    environmnet variables and the run verification step, as well as linking the read and write
    scaling settings into one function call.

    This will not be able to tell the difference between a table that is non-compliant and a table
    that is compliant. It is recommended that you run the detection method for auto-scaling compliance
    before you run this method to save cpu time.


    Parameters
    ----------
    table_name : str
        The name of the table to remediate for auto-scaling
    run_verify: bool
        If true, this will return the results of the table modification to check if
        the function ran as intended, and what the values were set to.

    Returns
    -------
    dict{"ReadResults": ReadResults, "WriteResults", WriteResults}
        If run_verify is true, this will return the results of the describe_scalable_targets
        api call after the modification to the table.

        Otherwise, it will return an empty dict for each read and write result
    """

    client.module.log(
        "Table name: {0} is being remediated for auto-scaling compliance".format(
            table_name
        )
    )

    # Pass in the parameters to the function by unwrapping the dict into named parameters
    res_read = apply_auto_scaling(client, region_name, table_name, "READ", **(params))
    res_write = apply_auto_scaling(client, region_name, table_name, "WRITE", **(params))

    # Combine results and return
    return {"ReadResults": res_read, "WriteResults": res_write}


def list_tables(client, region_name):
    """list all tables in a given region and account

    Returns
    -------
    dict:
        A dict which is the result of a call to dynamodb list_tables. The results are first paginated and then
        built into a singular result.

        Structure is as below:

        [
            'TableName1',
            'TableName2',
            ...
            'TableNameN'
        ]
    """

    dynamo_client = client.session.client("dynamodb", region_name=region_name)

    # Get paginator for the dynamodb client for the list_tables endpoint
    paginator = dynamo_client.get_paginator("list_tables")
    # Collect and combine all results into a single response
    results = paginator.paginate().build_full_result()["TableNames"]

    return results


def detect_point_in_time_compliance(client, region_name, table_name):
    """Detect Point-In-Time Restore compliance for a DynamoDB table

    Detects whether the given table name corresponds to a table in the given account and region,
    and whether that table is compliant with Point-In-Time Restore. This checks to see if
    Point-In-Time Restore is enabled for a given table.

    Parameters
    ----------
    table_name : str
        The name of the table to check for point-in-time restore compliance status

    Returns
    -------
    bool:
        True if the table is either compliant with point-in-time restore, or if the table
        does not exist. This is because if the table does not exist, technically it is
        not in compliance violation, and therefore is compliant by default

        False otherwise
    """

    module = client.module

    dynamo_client = client.session.client("dynamodb", region_name=region_name)

    # try:
    # Point-In-Time properties are stored as continuous backup information
    response = dynamo_client.describe_continuous_backups(TableName=table_name)
    # except Exception as e:
    #     print("\nError, an exception was raised in detect_point_in_time_compliance:")
    #     print(e)
    #     print('')
    #     return True # If the table doesn't exist, it is technically not not-compliant, therefore compliant

    # Get the string value for if Point-In-Time restore is enabled or not
    point_in_time_enabled = response["ContinuousBackupsDescription"][
        "PointInTimeRecoveryDescription"
    ]["PointInTimeRecoveryStatus"]

    current_point_in_time_recovery_setting = (
        "{0} has point-in-time recovery set to {1}\n".format(
            table_name, point_in_time_enabled
        )
    )
    client.module.debug(current_point_in_time_recovery_setting)
    # Convert string to boolean
    if point_in_time_enabled == "ENABLED":
        client.module.log(
            "Table name {0} is compliant with point-in-time recovery.".format(
                table_name
            )
        )
        return True
    else:
        client.module.log(
            "Table name {0} is not compliant with point-in-time recovery.".format(
                table_name
            )
        )
        return False


def detect_auto_scaling_compliance(client, region_name, table_name):
    """Detect Read/Write Auto-Scaling compliance for a DynamoDB table

    Detects whether the given table name corresponds to a table in the given account and region,
    and whether that table is compliant with Read/Write Auto-Scaling. This means that the table
    must be able to scale up or down in read/write capacity automatically.

    A failure of compliance with either/both read/write capacity will result in a non-compliant
    result.

    Parameters
    ----------
    table_name : str
        The name of the table to check for point-in-time restore compliance status

    Returns
    -------
    bool:
        True if the table is either compliant with Read/Write Auto-Scaling, or if the table
        does not exist. This is because if the table does not exist, technically it is
        not in compliance violation, and therefore is compliant by default

        False otherwise
    """

    dynamo_client = client.session.client("dynamodb", region_name=region_name)
    application_scaling_client = client.session.client(
        "application-autoscaling", region_name=region_name
    )

    # Check if the table exists and gather general table information
    # try:
    table_description = dynamo_client.describe_table(TableName=table_name)
    # except Exception as e:
    #     print("\nError, an exception was raised in detect_auto_scaling_compliance:")
    #     print(e)
    #     print('')
    #     return True

    try:
        # Check if the table has PAY_PER_REQUEST Capacity or is PROVISIONED
        billing_mode = table_description["Table"]["BillingModeSummary"]["BillingMode"]
    except KeyError:
        # It only contains "BillingModeSummary" if it is PAY_PER_REQUEST
        billing_mode = ""

    # PAY_PER_REQUEST tables auto-scale by default
    if billing_mode == "PAY_PER_REQUEST":

        current_auto_scaling_settings = (
            "{0} is {1} and conforms to AWS defaults.\n".format(
                table_name, billing_mode
            )
        )
        client.module.debug(current_auto_scaling_settings)
        return True

    # Get scalable attributes of the table
    res = application_scaling_client.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=["table/{0}".format(table_name)]
    )
    scalable_targets = res["ScalableTargets"]

    # Collect table read and table write scaling attributes
    target_dimensions = [
        target
        for target in scalable_targets
        if target["ScalableDimension"]
        in ["dynamodb:table:ReadCapacityUnits", "dynamodb:table:WriteCapacityUnits"]
    ]

    # If both don't exist, then it is not compliant
    if len(target_dimensions) == 0:
        client.module.log(
            "Table name {0} is not compliant with auto-scaling".format(table_name)
        )

        current_auto_scaling_settings = (
            "{0} does not scale via Read or Write Capacity.\n".format(table_name)
        )
        client.module.debug(current_auto_scaling_settings)
        return False
    elif len(target_dimensions) == 1:
        client.module.log(
            "Table name {0} is not compliant with auto-scaling".format(table_name)
        )
        if (
            target_dimensions[0]["ScalableDimension"]
            == "dynamodb:table:ReadCapacityUnits"
        ):
            current_auto_scaling_settings = (
                "{0} does not scale via Write Capacity.\n".format(table_name)
            )
        else:
            current_auto_scaling_settings = (
                "{0} does not scale via Read Capacity.\n".format(table_name)
            )
        client.module.debug(current_auto_scaling_settings)
        return False

    for target in target_dimensions:
        current_auto_scaling_settings = """{0} has a max capacity of {1}
        and a min capactiy of {2} for {3}\n""".format(
            table_name,
            target["MaxCapacity"],
            target["MinCapacity"],
            target["ScalableDimension"],
        )
        client.module.debug(current_auto_scaling_settings)
        # Max capacity must be greater than min capacity for any auto-scaling to take place
        if target["MinCapacity"] == target["MaxCapacity"]:
            client.module.log(
                "Table name {0} is not compliant with auto-scaling".format(table_name)
            )
            return False

    # Passed all checks
    client.module.log(
        "Table name {0} is compliant with auto-scaling".format(table_name)
    )

    return True


def get_account_id(client):
    """
    Return the twelve digit account id associated with this instance

    Returns
    ----------
    str :
        The twelve digit account id as a string.
    """

    sts_client = client.session.client("sts")

    return sts_client.get_caller_identity().get("Account")
