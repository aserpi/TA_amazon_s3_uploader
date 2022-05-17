import import_declare_test  # Always put this line at the beginning of this file

import csv
import gzip
import io
import json
import re
import os
from datetime import datetime

import boto3
from botocore.config import Config
from solnlib import conf_manager


APP_NAME = __file__.split(os.path.sep)[-4]
# Each non-meta field '<FIELD>' has a corresponding entry
# '__mv_<FIELD>' in the results. Multivalue fields are formatted as
# $value_1$;$value_2$;...;$value_n$ and dollar signs are doubled.
MV_FIELD_REGEX = re.compile(r"__mv_(.*)")
MV_VALUE_REGEX = re.compile(r'\$(?P<item>(?:\$\$|[^$])*)\$(?:;|$)')


def get_credentials(helper):
    """Get AWS credentials."""
    aws_account = helper.get_param("account")
    helper.log_debug(f"Found AWS account '{aws_account}'")

    conf_file = f"{APP_NAME.lower()}_account"
    cfm = conf_manager.ConfManager(helper.session_key, APP_NAME,
                                   realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{conf_file}")
    account = cfm.get_conf(conf_file).get(aws_account)
    return account["aws_key_id"], account["aws_secret"], account.get("aws_session_token")


def get_proxies(helper):
    """Get proxy settings."""
    proxy = helper.get_proxy()
    if not proxy:
        return None

    if proxy["proxy_username"] and proxy["proxy_password"]:
        proxy_url = (f"{proxy['proxy_type']}://"
                     f"{proxy['proxy_username']}:{proxy['proxy_password']}@"
                     f"{proxy['proxy_url']}:{proxy['proxy_port']}")
    else:
        proxy_url = f"{proxy['proxy_type']}://{proxy['proxy_url']}:{proxy['proxy_port']}"

    proxies = {proxy['proxy_type']: proxy_url}
    helper.log_debug(f"Found proxies: {proxies}")
    return proxies


def upload_csv_to_s3(raw_results, bucket, object_key, aws_access_key, aws_secret_key,
                     aws_session_token, proxies):
    """Upload a (potentially compressed) CSV file to an AWS S3 bucket."""
    results = []
    for raw_result in raw_results:
        result = {}
        for field in filter(lambda f: f.startswith("__mv_"), raw_result):
            field_name = MV_FIELD_REGEX.fullmatch(field).group(1)
            result[field_name] = raw_result[field_name]
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
                upload_to_s3(gzip_buffer, bucket, object_key, aws_access_key, aws_secret_key,
                             aws_session_token, proxies)
        else:
            upload_to_s3(csv_buffer.getvalue().encode(), bucket, object_key, aws_access_key,
                         aws_secret_key, aws_session_token, proxies)


def upload_json_to_s3(raw_results, bucket, object_key, aws_access_key, aws_secret_key,
                      aws_session_token, proxies):
    """Upload a JSON file to an AWS S3 bucket."""
    results = []
    for raw_result in raw_results:
        result = {}
        for field_name, field_values in filter(lambda i: i[0].startswith("__mv_"), raw_result.items()):
            field_name = MV_FIELD_REGEX.fullmatch(field_name).group(1)
            if field_values:  # Multivalue field
                mv = [match.replace("$$", "$") for match in MV_VALUE_REGEX.findall(field_values)]
                result[field_name] = mv
            else:  # Single-value field
                result[field_name] = raw_result[field_name]
        results.append(result)
    upload_to_s3(json.dumps(results).encode(), bucket, object_key, aws_access_key,
                 aws_secret_key, aws_session_token, proxies)


def upload_to_s3(results, bucket, object_key, aws_access_key, aws_secret_key, aws_session_token,
                 proxies):
    """Upload a file-like object to an AWS S3 bucket."""
    s3 = boto3.resource("s3", aws_access_key_id=aws_access_key,
                        aws_secret_access_key=aws_secret_key, aws_session_token=aws_session_token,
                        config=Config(proxies=proxies))
    s3_object = s3.Object(bucket, object_key)
    s3_object.put(Body=results)


def process_event(helper, *args, **kwargs):
    """
    Do not remove: sample code generator
    [sample_code_macro:start]
    [sample_code_macro:end]
    """
    helper.log_info("Alert action aws_s3_upload started.")

    try:
        aws_access_key, aws_secret_key, aws_session_token = get_credentials(helper)
    except KeyError:
        helper.log_error("Cannot find credentials for the account")
        return 3
    proxies = get_proxies(helper)

    bucket = helper.get_param("bucket_name")
    helper.log_debug(f"Found bucket '{bucket}'")
    object_key = helper.get_param("object_key")
    helper.log_debug(f"Found object key '{object_key}'")
    object_key = datetime.now().astimezone().strftime(object_key)
    helper.log_debug(f"Parsed object key {object_key}")

    # TODO: check for file existence
    # splunktaucclib calls sys.exit if there are no results
    results = helper.get_events()

    if object_key.endswith(".csv") or object_key.endswith(".csv.gz"):
        upload_csv_to_s3(results, bucket, object_key, aws_access_key, aws_secret_key,
                         aws_session_token, proxies)
    elif object_key.endswith(".json"):
        upload_json_to_s3(results, bucket, object_key, aws_access_key, aws_secret_key,
                          aws_session_token, proxies)
    else:
        helper.log_error("Unsupported file extension")
        return 3

    helper.log_info("Alert action aws_s3_upload completed.")
    return 0
