# Huawei Cloud WAF certificate updater

This repository contains an automation script to update the TLS certificate
and private key configured in a [Huawei Cloud Web Application Firewall (WAF)][waf]
instance, by loading the updated contents from local files.

## Suggested usage

If you have a Kubernetes application and use [cert-manager](https://cert-manager.io/)
to manage TLS certificates, you can do the following:

1. Build a Docker image and push to the container registry of your choice
   (example with [Huawei Cloud Software Repository for Container (SWR)][swr-qs]);
2. Deploy in your Kubernetes cluster as a CronJob that runs once a day
   (see `kubernetes-manifest.yaml` as an example).

To manually run the CronJob without waiting for the scheduled time, use the
following command:

```shell
kubectl create job --from=cronjob/waf-cert-updater-example-domain \
  waf-cert-updater-example-domain-manual-$(date +%s) -n istio-system
```

Please note that if several certificates are managed by cert-manager, you need
to deploy one CronJob for each certificate.

## How the automation works

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

According to the [best practices for using IAM][iam-best-practices], it is a
standard security measure to grant users only the permissions required to
perform specific tasks. The principle of least privilege (PoLP) helps you
establish secure access to your Huawei Cloud resources.

Therefore, an IAM user should be created exclusively for this automation, with
the following [IAM policy][iam-policy] assigned:

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
[swr-qs]: <https://support.huaweicloud.com/intl/en-us/qs-swr/index.html>
[iam-best-practices]: <https://support.huaweicloud.com/intl/en-us/bestpractice-iam/iam_0426.html>
[iam-policy]: <https://support.huaweicloud.com/intl/en-us/usermanual-iam/iam_01_0605.html>
