# Amazon S3 Uploader for Splunk

![GitHub release (latest by date)](https://img.shields.io/github/v/release/aserpi/TA_amazon_s3_uploader)
![License](https://img.shields.io/github/license/aserpi/TA_amazon_s3_uploader)
![Splunk Enterprise](https://img.shields.io/badge/Splunk%20Enterprise-10.2+-67a53e?logo=splunk)
![Splunk Cloud](https://img.shields.io/badge/Splunk%20Cloud-10.2%2B-ed0080?logo=splunk)

This Splunk add-on delivers an alert action that uploads search results to an Amazon (AWS) S3 bucket.


## Object keys

Object keys uniquely identify objects in an Amazon S3 bucket. Although all UTF-8 characters are allowed, some should be avoided. Forward slashes can be used to mimic a directory structure. Please refer to the [official documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html) for additional information.

### Supported file types

The output format is inferred from the object key extension. Only uncompressed and gzip-compressed CSV and JSON files (`.csv`, `.csv.gz`, `.json`, `.json.gz`) are supported.

Multivalue fields are treated differently based on the output format: in JSON they are stored as an array, while in CSV they are in a single entry, separated by their delimiter (by default a newline). For example, the search
```spl
| makeresults
| eval test=split("value1,value2", ",")
| fields - _*
```
produces the CSV
```csv
test
"value1
value2"
```
whereas the search
```spl
| makeresults
| eval test="value1,value2"
| makemv delim="," test
| fields - _*
```
produces the CSV
```csv
test
"value1,value2"
```

Both searches generate the same JSON

```json
{"test": ["value1", "value2"]}
```

### Timestamp

The user-provided object key is passed to Python's `datetime.strftime()` function, which encodes the time the search started.
Format codes are extremely similar to Splunk's, please refer to the [official documentation](https://docs.python.org/3.7/library/datetime.html#strftime-strptime-behavior).

### Type casting

JSON files support opt-in type casting for values that comply with the JSON standard.
When enabled, each field is analyzed across all results to infer its type:

1. If every non-empty value in the field can be parsed as a Python `int`, the field is cast to an integer number.
2. Otherwise, if every non-empty value can be parsed as a finite Python `float` (i.e., neither infinity nor NaN), the field is cast to a decimal fraction.
3. Otherwise, the field is kept as a string.

Empty strings represent missing values in Splunk and are converted to `null`.

The parsing of numbers is delegated to the Python functions `float()` and `int()`, which can parse strings that are not normally perceived as numbers.
For example, the search

```
| makeresults
| eval i1=11,
    i2=" 1_2 ",
    f=".5",
    mv=split("1,2,text", ","),
    "n": "",
    s="abc"
| fields - _*
```

produces without type casting

```json
[{"i1": "11", "i2": " 1_2 ", "f": ".5", "s": "abc", "mv": ["1", "2", "text"], "n": ""}]
```

and with type casting

```json
[{"i1": 11, "i2": 12, "f": 0.5, "s": "abc", "mv": ["1", "2", "text"], "n": null}]
```


## Configuration

The add-on must be configured prior to its use. The setup is performed through a configuration page with tabs dedicated to accounts, web proxy, and logging level.

### Accounts

Unless Boto3's default authentication method is used, it is necessary to configure at least an AWS IAM user with write privileges on the bucket. Temporary security credentials (which have a session token in addition to the access key ID and the secret access key) are supported, but should be used for test purposes only.

Use the account `Boto3` to use Boto3's default authentication method. Please refer to the [official documentation](https://boto3.amazonaws.com/v1/documentation/api/1.28.1/index.html) for the order in which Boto3 searches for credentials. If this method is account, then manually specifying a role has no effect.

### Proxy

HTTP and HTTPS proxy servers, both authenticated and unauthenticated, are supported.

All communications with AWS servers use HTTPS. The option _Disable SSL verification_ disables checks on the server's certificate, it should not be used unless necessary (e.g., the proxy performs TLS bridging with certificates signed by an untrusted CA).

### Logging

The log file is stored in `$SPLUNK_HOME/var/log/splunk/log/amazon_s3_uploader_modalert.csv`. The default logging level is `INFO`, but it can be increased or decreased from the configuration dashboard.


## Development

This add-on uses Splunk's [UCC](https://splunk.github.io/addonfactory-ucc-generator/). Please refer to its documentation for how to build the add-on.
