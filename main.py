import os
import json
from dotenv import load_dotenv
from enum import Enum, StrEnum, auto
from datetime import datetime

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkwaf.v1 import WafClient, ShowCertificateRequest, ShowCertificateResponse as WafCertificate, UpdateCertificateRequest, UpdateCertificateRequestBody
from huaweicloudsdkwaf.v1.region.waf_region import WafRegion


class ExitCode(Enum):
    ENV_ERROR = -1
    GET_WAF_CERT_ERROR = -2
    GET_LOCAL_CERT_ERROR = -3
    UPDATE_WAF_CERT_ERROR = -4
    UNSPECIFIED = -99


def abort(exit_code: ExitCode):
    print("Aborting, reason:", exit_code.name)
    exit(exit_code.value)


def check_required_env_vars():
    load_dotenv(override=False)

    REQUIRED = [
        # credentials of IAM user with permission to read
        # and update WAF certificates
        "CLOUD_SDK_AK", "CLOUD_SDK_SK",

        # Region code (e.g. "sa-brazil-1" for LA-Sao Paulo1)
        "CLOUD_REGION",

        # ID of certificate in WAF to be updated by this script
        "WAF_CERTIFICATE_ID",
    ]

    for var in REQUIRED:
        var_value = os.getenv(var, "")
        if len(var_value.strip()) == 0:
            print(f"ERROR: environment variable '{var}' not set or empty")
            abort(ExitCode.ENV_ERROR)


def build_waf_client(ak: str, sk: str, region_code: str) -> WafClient:
    """Buils a WAF Client from Huawei Cloud WAF SDK, used later to invoke
    WAF APIs.

    Args:
        ak (str): access key from IAM user with WAF permissions
        sk (str): secret access key from IAM user with WAF permissions
        region_code (str): region where WAF is deployed, e.g. "sa-brazil-1"
            for LA-Sao Paulo1 region.

    Returns:
        WafClient: to be used in API invoking
    """
    credentials = BasicCredentials(ak, sk)

    waf_client = WafClient.new_builder() \
        .with_credentials(credentials) \
        .with_region(WafRegion.value_of(region_code)) \
        .build()

    return waf_client


def get_waf_certificate(waf_client: WafClient, certificate_id: str) -> WafCertificate:
    """Invokes the ShowCertificate API to obtain the contents of the
    TLS certificate in WAF service.

    Aborts with GET_WAF_CERT_ERROR if API invoking failed.

    Args:
        waf_client (WafClient): client instance returned by build_waf_client()
        certificate_id (str): resource ID of certificate configured in WAF.

    Returns:
        str: TLS certificate contents
    """
    try:
        request = ShowCertificateRequest()
        request.certificate_id = certificate_id
        response: WafCertificate = waf_client.show_certificate(request)
    except exceptions.ClientRequestException as e:
        debug_info = {
            "status_code": e.status_code,
            "error_code": e.error_code,
            "error_msg": e.error_msg
        }
        print("ERROR: failed to get certificate content -", debug_info)
        abort(ExitCode.GET_WAF_CERT_ERROR)

    configured_at = datetime.fromtimestamp(int(response.timestamp / 1000))
    expires_at = datetime.fromtimestamp(response.expire_time / 1000)
    msg = f"WAF certificate obtained, configured at {configured_at}, "
    msg += f"expires at {expires_at}"
    print(msg)

    return response


def get_local_certificate_and_key() -> tuple[str, str]:
    """Load certificate file "tls.crt" and private key file "tls.key" from
    "cert" folder in the same folder as this script.

    Aborts with GET_LOCAL_CERT_ERROR if the files could not be loaded.

    No validation is performed on the files' contents.

    Returns:
        tuple[str, str]: first element is the certificate file contents,
            and the second element is the private key file contents.
    """
    input_path = os.path.dirname(__file__)
    input_path = os.path.join(input_path, 'cert')

    TLS_FILES = {
        'certificate': 'tls.crt',
        'private_key': 'tls.key',
    }

    # keys are the same as TLS_FILES, values are the files' contents
    tls_contents: dict[str, str] = {}

    for file_type, filename in TLS_FILES.items():
        FILE_PATH = os.path.join(input_path, filename)
        file_lines = None
        try:
            with open(FILE_PATH, 'r') as tls_file:
                # load as separate lines, removing line endings
                file_lines = [line.strip() for line in tls_file.readlines()]
        except:
            print(f"ERROR: failed to read local {file_type} at {FILE_PATH}")
            abort(ExitCode.GET_LOCAL_CERT_ERROR)

        # join lines in a single str, using "\n" to concatenate (same as WAF)
        tls_contents[file_type] = "\n".join(file_lines)

    return tls_contents['certificate'], tls_contents['private_key']


def is_update_needed(waf_certificate: WafCertificate, local_certificate: str) -> bool:
    """Returns True if waf_certificate is different than local_certificate.

    Args:
        waf_certificate (str): certificate currently configured on WAF service
        local_certificate (str): certificate managed locally
            e.g. by cert-manager

    Returns:
        bool: False if certificates are equal
    """
    is_different = waf_certificate.content.strip() != local_certificate.strip()
    return is_different


def update_waf_certificate(
        waf_client: WafClient,
        current_waf_certificate: WafCertificate,
        new_certificate: str,
        new_private_key: str):
    try:
        # DOES NOT WORK!
        # {'status_code': 400, 'error_code': 'WAF.00022003', 'error_msg': 'Resource is in use'}

        # TODO: check API sequence on Console

        request = UpdateCertificateRequest()
        request.certificate_id = current_waf_certificate.id
        request.body = UpdateCertificateRequestBody(
            key=new_private_key,
            content=new_certificate,
            name=current_waf_certificate.name  # unchanged, but it's mandatory
        )
        response = waf_client.update_certificate(request)
    except exceptions.ClientRequestException as e:
        debug_info = {
            "status_code": e.status_code,
            "error_code": e.error_code,
            "error_msg": e.error_msg
        }
        print("ERROR: failed to update certificate content -", debug_info)
        abort(ExitCode.UPDATE_WAF_CERT_ERROR)

    print(response)


def main():
    check_required_env_vars()

    waf_client = build_waf_client(
        ak=os.getenv("CLOUD_SDK_AK"),
        sk=os.getenv("CLOUD_SDK_SK"),
        region_code=os.getenv("CLOUD_REGION")
    )

    waf_certificate = get_waf_certificate(
        waf_client=waf_client,
        certificate_id=os.getenv("WAF_CERTIFICATE_ID"))

    local_certificate, local_private_key = get_local_certificate_and_key()

    if not is_update_needed(waf_certificate, local_certificate):
        print("WAF certificate is the same as local certificate")
        print("No action is needed. Bye.")
        exit(0)

    update_waf_certificate(
        waf_client=waf_client,
        current_waf_certificate=waf_certificate,
        new_certificate=local_certificate,
        new_private_key=local_private_key)


if __name__ == "__main__":
    main()
