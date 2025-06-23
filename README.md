# Huawei Cloud WAF certificate updater

This repository contains an automation script to update the TLS certificate
and private key configured in a
[Huawei Cloud Web Application Firewall (WAF)][waf] instance, by loading the
updated contents from local files.

## Explanation

Since it's not possible to update the active certificate directly, two
certificates (A and B) should be registered in the WAF instance, where one of
them is active and the other is standby. In this scenario, given that
certificate A is currently active and certificate B is standby, this
automation script performs the following steps:

1. Fetch the contents and details of certificate A and the certificate B from
   WAF service;
2. Load the contents and details of the local certificate and private key
   files;
3. Compare the contents of the local certificate with the WAF certificate A
   which currently active. If the contents are equal, nothing is done and the
   script finishes;
4. Update the standby certificate B in WAF service using the contents of local
   certificate and private key files;
5. Update all domains associated with the active certificate A, making them
   use the now updated standby certificate B;
6. The script finishes, making certificate B active and certificate A standby.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLOUD_SDK_AK` | yes | - | Access Key (AK) for IAM user with permission to update WAF certificate |
| `CLOUD_SDK_SK` | yes | - | Secret Access Key (SK) for IAM user with permission to update WAF certificate |
| `CLOUD_REGION` | yes | - | Region code (e.g. `sa-brazil-1` for LA-Sao Paulo1 region) where WAF instance is deployed |
| `WAF_CERTIFICATE_A_ID` | yes | - | Resource ID of WAF certificate A |
| `WAF_CERTIFICATE_B_ID` | yes | - | Resource ID of WAF certificate B |
| `LOCAL_CERT_PATH` | no | `/usr/src/app/cert` | Path where the certificate and the private key files are located |
| `LOCAL_CERT_NAME` | no | `tls` | Name (without extension) of certificate and private key files |

By default, the automation script will try to load the local certificate
content from `/usr/src/app/cert/tls.crt` file and the private key content from
`/usr/src/app/cert/tls.key` file, unless environment variables
`LOCAL_CERT_PATH` and `LOCAL_CERT_NAME` are specified.

## Log messages

For reference, below are listed some example log messages.

When nothing needs to be done:

```plain
2025-06-23 11:14:24,615 INFO WAF certificate 'example-cert-name_certA' obtained (active), expires at 2026-06-23 10:56:26
2025-06-23 11:14:24,906 INFO WAF certificate 'example-cert-name_certB' obtained , expires at 2026-06-23 10:49:18
2025-06-23 11:14:24,907 INFO Active WAF cert is the same as local cert
2025-06-23 11:14:24,907 INFO No action is needed. Bye.
```

When the WAF certificate is updated:

```plain
2025-06-23 11:51:28,790 INFO WAF certificate 'example-cert-name_certA' obtained (active), expires at 2026-06-23 10:56:26
2025-06-23 11:51:29,088 INFO WAF certificate 'example-cert-name_certB' obtained , expires at 2026-06-23 10:49:18
2025-06-23 11:51:29,089 INFO Updating WAF certificate example-cert-name_certB...
2025-06-23 11:51:30,802 INFO Update and switchover performed successfully
```

When AK/SK is invalid:

```plain
2025-06-23 11:58:14,810 ERROR Failed to initialize WAF client, check AK/SK
2025-06-23 11:58:14,811 ERROR Aborting, reason: BUILD_WAF_CLIENT_ERROR
```

## IAM user permissions required

```json
{
  "Version": "1.1",
  "Statement": [
    {
      "Action": [
        "waf:certificate:get",
        "waf:certificate:put",
        "waf:certificate:list",
        "waf:certificate:apply"
      ],
      "Effect": "Allow"
    }
  ]
}
```

[waf]: <https://support.huaweicloud.com/intl/en-us/waf/index.html>