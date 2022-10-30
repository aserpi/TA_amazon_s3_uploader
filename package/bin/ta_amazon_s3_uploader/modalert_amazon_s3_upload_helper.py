import import_declare_test  # Always put this line at the beginning of this file

import csv
import gzip
import io
import json
import os
import re
from datetime import datetime, timezone

import boto3
import botocore.config
import botocore.exceptions
from solnlib import conf_manager


# Each non-meta field '<FIELD>' has a corresponding entry
# '__mv_<FIELD>' in the results. Multivalue fields are formatted as
# $value_1$;$value_2$;...;$value_n$ and dollar signs are doubled.
MV_VALUE_REGEX = re.compile(r'\$(?P<item>(?:\$\$|[^$])*)\$(?:;|$)')


def get_credentials(helper, aws_config):
    """Get AWS credentials."""
    aws_account = helper.get_param("account")
    helper.log_debug(f"Found AWS account '{aws_account}'")

    credentials = helper.get_user_credential_by_account_id(aws_account)
    if not credentials:
        helper.log_error("AWS account not found in configuration file.")
        return {}
    aws_credentials = {
        "aws_access_key_id": credentials.get("aws_key_id"),
        "aws_secret_access_key": credentials.get("aws_secret"),
        "aws_session_token": credentials.get("aws_session_token"),
    }

    if not aws_credentials["aws_access_key_id"]:
        helper.log_error("Missing AWS access key ID.")
        return {}
    if not aws_credentials["aws_secret_access_key"]:
        helper.log_error("Missing AWS secret access key.")
        return {}

    aws_role = helper.get_param("role")
    if not aws_role:
        return aws_credentials
    helper.log_debug(f"Found AWS role {aws_role}.")

    cfm = conf_manager.ConfManager(helper.session_key, helper.ta_name)
    try:
        roles = cfm.get_conf("ta_amazon_s3_uploader_role")
        aws_role = roles.get(aws_role)["aws_arn"]
    except (KeyError, conf_manager.ConfManagerException, conf_manager.ConfStanzaNotExistException):
        helper.log_error("Role not found in configuration file.")
        return {}

    sts = boto3.client("sts", **aws_credentials, **aws_config)
    try:
        credentials = sts.assume_role(RoleArn=aws_role,
                                      RoleSessionName="AmazonS3UploaderForSplunk",
                                      DurationSeconds=3600)["Credentials"]
    except botocore.exceptions.ClientError as e:
        helper.log_error(f"Cannot assume role: {e.response['Error']['Message']}")
        return {}

    return {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }


def get_proxies(helper):
    """Get proxy settings."""
    proxy = helper.get_proxy()
    if not proxy:
        return {}

    if proxy["proxy_username"] and proxy["proxy_password"]:
        proxy_url = (f"{proxy['proxy_type']}://"
                     f"{proxy['proxy_username']}:{proxy['proxy_password']}@"
                     f"{proxy['proxy_url']}:{proxy['proxy_port']}")
    else:
        proxy_url = f"{proxy['proxy_type']}://{proxy['proxy_url']}:{proxy['proxy_port']}"

    proxies = {proxy['proxy_type']: proxy_url}
    helper.log_debug(f"Found proxies: {proxies}.")
    verify_ssl = not helper.get_global_setting("disable_verify_ssl")
    helper.log_debug(f"Found disable_verify_ssl '{verify_ssl}'.")

    return {"config": botocore.config.Config(proxies), "verify": verify_ssl}


def upload_csv_to_s3(raw_results, bucket, object_key, aws_credentials, aws_config):
    """Upload a (potentially compressed) CSV file to an Amazon S3 bucket."""
    results = []
    for raw_result in raw_results:
        result = {}
        for field_name in (n for n in raw_result if n.startswith("__mv_")):
            field_name = field_name[5:]
            result[field_name] = raw_result[field_name]  # Save the raw value
        results.append(result)
    with io.StringIO() as csv_buffer:
        writer = csv.DictWriter(csv_buffer, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
        if object_key.endswith(".csv.gz"):
            with io.BytesIO() as gzip_buffer:
                with gzip.open(gzip_buffer, mode="w") as gzip_file:
                    gzip_file.write(csv_buffer.getvalue().encode())
                gzip_buffer.seek(0)  # Return to the start of the buffer
                upload_to_s3(gzip_buffer, bucket, object_key, aws_credentials, aws_config)
        else:
            upload_to_s3(csv_buffer.getvalue().encode(), bucket, object_key, aws_credentials,
                         aws_config)


def upload_json_to_s3(raw_results, bucket, object_key, aws_credentials, aws_config):
    """Upload a JSON file to an Amazon S3 bucket."""
    results = []
    for raw_result in raw_results:
        result = {}
        mv_fields = ((n, v) for n, v in raw_result.items() if n.startswith("__mv_"))
        for field_name, field_values in mv_fields:
            field_name = field_name[5:]
            if field_values:  # Multivalue field
                mv = [match.replace("$$", "$") for match in MV_VALUE_REGEX.findall(field_values)]
                result[field_name] = mv
            else:  # Single-value field
                result[field_name] = raw_result[field_name]
        results.append(result)
    upload_to_s3(json.dumps(results).encode(), bucket, object_key, aws_credentials, aws_config)


def upload_to_s3(results, bucket, object_key, aws_credentials, aws_config):
    """Upload a file-like object to an Amazon S3 bucket."""
    s3 = boto3.resource("s3", use_ssl=True, **aws_credentials, **aws_config)
    s3_object = s3.Object(bucket, object_key)
    s3_object.put(Body=results)


def process_event(helper, *args, **kwargs):
    """
    Do not remove: sample code generator
    [sample_code_macro:start]
    [sample_code_macro:end]
    """
    helper.log_info("Alert action amazon_s3_upload started.")

    aws_config = get_proxies(helper)
    aws_region = helper.get_param("aws_region")
    if aws_region:
        helper.log_debug(f"Found region '{aws_region}'.")
        aws_config["region_name"] = aws_region

    aws_credentials = get_credentials(helper, aws_config)
    if not aws_credentials:
        return 11

    bucket = helper.get_param("bucket_name")
    helper.log_debug(f"Found bucket '{bucket}'.")
    object_key = helper.get_param("object_key")
    helper.log_debug(f"Found object key '{object_key}'.")

    helper.addinfo()
    tz = timezone.utc if helper.get_param("utc") else None
    search_time = datetime.fromtimestamp(float(helper.info['_timestamp'])).astimezone(tz)
    object_key = search_time.strftime(object_key)
    helper.log_debug(f"Parsed object key '{object_key}'.")

    # splunktaucclib calls sys.exit if there are no results
    if os.path.isfile(helper.results_file):
        results = helper.get_events()
    elif helper.get_param("upload_empty"):
        results = []
    else:
        return 0

    if object_key.endswith(".csv") or object_key.endswith(".csv.gz"):
        upload_csv_to_s3(results, bucket, object_key, aws_credentials, aws_config)
    elif object_key.endswith(".json"):
        upload_json_to_s3(results, bucket, object_key, aws_credentials, aws_config)
    else:
        helper.log_error("Unsupported file extension.")
        return 3

    helper.log_info("Alert action amazon_s3_upload completed.")
    return 0
