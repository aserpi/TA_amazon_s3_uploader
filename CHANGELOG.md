# Changelog

## 2.1.1 - 2026-04-25

Update dependencies.

## 2.1.0 - 2026-03-15

Improvements:

- Add support for AWS China and GovCloud regions.  
- Allow impersonating a role with EC2 and container roles.  

Bug fixes:

- Avoid crashing when uploading empty CSV files.
- Fix the creation of proxy URLs.

## 2.0.1 - 2024-12-10

Use an original `splunktaucclib` that fixes the bug that prevented this add-on from working properly.

## 2.0.0 - 2024-11-23

Provide a custom `splunktaucclib` to fix a bug that prevented this add-on from working properly.

BREAKING CHANGE: Drop support for Splunk<9.3.0.
Amazon dropped support for Python 3.7 in their official AWS package.

## 1.1.1 - 2024-01-10

Update dependencies to comply with new Splunk Cloud requirements.

## 1.1.0 - 2023-07-11

Support Boto3's automatic credentials retrieval.  
Add support for Splunk Cloud.

## 1.0.3 - 2023-03-06

Fix deactivation of TSL certificate check.

## 1.0.2 - 2023-03-03

Fix incorrect REST root and UTC option field.

## 1.0.1 - 2023-02-10

Improve handling of empty results.

## 1.0.0 - 2022-10-30

Initial release
