# -*- coding: utf-8 -*-

"""
Automation script to update Huawei Cloud WAF certificate from local
certificate and private key files.

Since a certificate in use cannot be updated directly, two WAF certificates
are expected: an active (in use) and a standby (idle) certificate.

This script compares the local certificate file with the active certificate,
and if they are different, the standby certificate is updated with the
contents of the local certificate, and then the standby certificate is
associated with all WAF domains currently associated with the active
certificate.

Author: Gabriel Gutierrez Pereira Soares <gabrielg.soares@huawei.com>
Created: 2025-04-01
Last Modified: 2025-06-23
"""

import logging
import os
from datetime import datetime
from enum import Enum

from dotenv import load_dotenv
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkwaf.v1 import (ApplyCertificateToHostRequest,
                                  ApplyCertificateToHostRequestBody, BindHost,
                                  ShowCertificateRequest,
                                  ShowCertificateResponse,
                                  UpdateCertificateRequest,
                                  UpdateCertificateRequestBody, WafClient)
from huaweicloudsdkwaf.v1.region.waf_region import WafRegion


class ExitCode(Enum):
    ENV_ERROR = -1
    GET_WAF_CERT_ERROR = -2
    GET_LOCAL_CERT_ERROR = -3
    UPDATE_WAF_CERT_ERROR = -4
    BOTH_WAF_CERTS_IN_USE = -5
    SWITCHOVER_WAF_CERT_ERROR = -6
    BUILD_WAF_CLIENT_ERROR = -7
    UNSPECIFIED = -99


class LocalCertificate:
    """Holds the contents of local certificate and private key files
    """
    def __init__(self, content: str, private_key: str):
        self._content = content.strip()
        self._private_key = private_key.strip()

    @property
    def content(self):
        return self._content

    @property
    def private_key(self):
        return self._private_key


class WafHost:
    """In WAF, a host is a domain name configured in a specific WAF type
    """
    def __init__(self, host: BindHost):
        self._id = host.id
        self._waf_type = host.waf_type

    @property
    def id(self):
        return self._id

    @property
    def waf_type(self):
        return self._waf_type

    @property
    def is_cloud_type(self):
        return self._waf_type == 'cloud'

    @property
    def is_premium_type(self):
        return self._waf_type == 'premium'


class WafCertificate:
    """Holds the contents and details of a WAF certificate
    """
    def __init__(self, show_cert_response: ShowCertificateResponse):
        self._id: str = show_cert_response.id
        self._name: str = show_cert_response.name.strip()
        self._content: str = show_cert_response.content.strip()

        self._configured_at: datetime = datetime.fromtimestamp(
            int(show_cert_response.timestamp / 1000))

        self._expires_at: datetime = datetime.fromtimestamp(
            show_cert_response.expire_time / 1000)

        self._hosts_bound: list[WafHost] = [
            WafHost(host) for host in show_cert_response.bind_host
        ]

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @property
    def content(self):
        return self._content

    @property
    def is_active(self):
        return len(self._hosts_bound) > 0

    @property
    def configured_at(self):
        return self._configured_at

    @property
    def expires_at(self):
        return self._expires_at

    @property
    def hosts_bound(self):
        return self._hosts_bound


def abort(exit_code: ExitCode):
    logging.error("Aborting, reason: %s", exit_code.name)
    exit(exit_code.value)


def check_required_env_vars():
    load_dotenv(override=False)

    REQUIRED = [
        # credentials of IAM user with permission to read
        # and update WAF certificates
        "CLOUD_SDK_AK", "CLOUD_SDK_SK",

        # Region code (e.g. "sa-brazil-1" for LA-Sao Paulo1)
        "CLOUD_REGION",

        # ID of WAF certificates A and B to be updated by this script
        "WAF_CERTIFICATE_A_ID", "WAF_CERTIFICATE_B_ID",
    ]

    for var in REQUIRED:
        var_value = os.getenv(var, "").strip()
        if len(var_value) == 0:
            logging.error("Environment variable '%s' not set or empty", var)
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

    try:
        waf_client = WafClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(WafRegion.value_of(region_code)) \
            .build()
    except exceptions.SdkException:
        logging.error("Failed to initialize WAF client, check AK/SK")
        abort(ExitCode.BUILD_WAF_CLIENT_ERROR)
    except KeyError:
        logging.error("Failed to initialize WAF client, invalid CLOUD_REGION")
        abort(ExitCode.BUILD_WAF_CLIENT_ERROR)

    return waf_client


def get_waf_certificate(
        waf_client: WafClient, certificate_id: str) -> WafCertificate:
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
        logging.error(
            "Failed to get certificate %s content - %s",
            certificate_id, debug_info)
        abort(ExitCode.GET_WAF_CERT_ERROR)

    waf_cert = WafCertificate(response)

    active = '(active)' if waf_cert.is_active else ''
    msg = f"WAF certificate '{waf_cert.name}' obtained {active}, "
    msg += f"expires at {waf_cert.expires_at}"
    logging.info(msg)

    return waf_cert


def get_local_certificate() -> LocalCertificate:
    """Load certificate file "tls.crt" and private key file "tls.key" from
    "cert" folder in the same folder as this script, or in folder set by
    LOCAL_CERT_PATH environment variable.

    Aborts with GET_LOCAL_CERT_ERROR if the files could not be loaded.

    No validation is performed on the files' contents.

    Returns:
        LocalCertificate: certificate and private key files' content.
    """
    DEFAULT_BASE_PATH = os.path.join(os.path.dirname(__file__), 'cert')
    CERT_BASE_PATH = os.getenv("LOCAL_CERT_PATH", DEFAULT_BASE_PATH)

    CERT_NAME = os.getenv("LOCAL_CERT_NAME", "tls")

    TLS_FILES = {
        'certificate': f"{CERT_NAME}.crt",
        'private_key': f"{CERT_NAME}.key",
    }

    # keys are the same as TLS_FILES, values are the files' contents
    tls_contents: dict[str, str] = {}

    for file_type, filename in TLS_FILES.items():
        FILE_PATH = os.path.join(CERT_BASE_PATH, filename)
        file_lines = None
        try:
            with open(FILE_PATH, 'r') as tls_file:
                # load as separate lines, removing line endings
                file_lines = [line.strip() for line in tls_file.readlines()]
        except Exception:
            logging.error(
                "Failed to read local %s at %s", file_type, FILE_PATH)
            abort(ExitCode.GET_LOCAL_CERT_ERROR)

        # join lines in a single str, using "\n" to concatenate (same as WAF)
        tls_contents[file_type] = "\n".join(file_lines)

    certificate = LocalCertificate(
        tls_contents['certificate'], tls_contents['private_key'])

    return certificate


def is_update_needed(
        waf_cert: WafCertificate,
        local_cert: LocalCertificate) -> bool:
    """Returns True if waf_certificate content is different than local_cert
    content.

    Args:
        waf_cert (WafCertificate): certificate currently configured
            on WAF service
        local_cert (LocalCertificate): certificate managed locally
            e.g. by cert-manager

    Returns:
        bool: False if certificates are equal
    """
    is_different = waf_cert.content != local_cert.content
    return is_different


def update_waf_certificate(
        waf_client: WafClient,
        current_waf_certificate: WafCertificate,
        new_certificate: LocalCertificate):
    """Updates the WAF certificate content with the new certificate content.

    This API can only be invoked if the certificate is not in use. That's
    the reason there is an active and a standby certificate.

    The active certificate is the one currently assigned to the WAF domains,
    while the standby certificate is not associated to any domains.

    If this API is invoked for a certificate that is assigned to a domain
    name, the following error code is returned:
    WAF.00022003 - Resource is in use

    Args:
        waf_client (WafClient): client instance returned by build_waf_client()
        current_waf_certificate (WafCertificate): standby WAF certificate
        new_certificate (LocalCertificate): local certificate
    """
    try:
        request = UpdateCertificateRequest()
        request.certificate_id = current_waf_certificate.id
        request.body = UpdateCertificateRequestBody(
            key=new_certificate.private_key,
            content=new_certificate.content,
            name=current_waf_certificate.name  # unchanged, but it's mandatory
        )
        waf_client.update_certificate(request)
    except exceptions.ClientRequestException as e:
        debug_info = {
            "status_code": e.status_code,
            "error_code": e.error_code,
            "error_msg": e.error_msg
        }
        logging.error("Failed to update certificate content - %s", debug_info)
        abort(ExitCode.UPDATE_WAF_CERT_ERROR)


def switchover_waf_certificates(
        waf_client: WafClient,
        active_cert: WafCertificate,
        standby_cert: WafCertificate):
    """Assigns the standby certificate to all hosts currently associated with
    the active certificate.

    Args:
        waf_client (WafClient): client instance returned by build_waf_client()
        active_cert (WafCertificate): certificate currently assigned to
            WAF domains
        standby_cert (WafCertificate): WAF certificate that should have been
            updated with the contents from the local certificate, using
            update_waf_certificate()
    """
    cloud_host_ids = []
    premium_host_ids = []

    for host in active_cert.hosts_bound:
        # A certificate can be assigned to multiple WAF domains, and
        # also with different WAF editions (cloud, premium), so we consolidate
        # all hosts here in order to execute a single API call
        if host.is_cloud_type:
            cloud_host_ids.append(host.id)
        elif host.is_premium_type:
            premium_host_ids.append(host.id)
        else:
            logging.error("Invalid WafHost type - %s", host.waf_type)
            abort(ExitCode.UNSPECIFIED)

    try:
        request = ApplyCertificateToHostRequest()
        request.certificate_id = standby_cert.id

        if len(cloud_host_ids) > 0:
            request.body = ApplyCertificateToHostRequestBody(
                cloud_host_ids=cloud_host_ids
            )

        if len(premium_host_ids) > 0:
            request.body = ApplyCertificateToHostRequestBody(
                premium_host_ids=premium_host_ids
            )

        waf_client.apply_certificate_to_host(request)
    except exceptions.ClientRequestException as e:
        debug_info = {
            "status_code": e.status_code,
            "error_code": e.error_code,
            "error_msg": e.error_msg
        }
        logging.error("Failed to switchover certificate - %s", debug_info)
        abort(ExitCode.SWITCHOVER_WAF_CERT_ERROR)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s')

    check_required_env_vars()

    waf_client = build_waf_client(
        ak=os.getenv("CLOUD_SDK_AK"),
        sk=os.getenv("CLOUD_SDK_SK"),
        region_code=os.getenv("CLOUD_REGION")
    )

    waf_cert_a = get_waf_certificate(
        waf_client=waf_client,
        certificate_id=os.getenv("WAF_CERTIFICATE_A_ID"))

    waf_cert_b = get_waf_certificate(
        waf_client=waf_client,
        certificate_id=os.getenv("WAF_CERTIFICATE_B_ID"))

    local_cert = get_local_certificate()

    if waf_cert_a.is_active and waf_cert_b.is_active:
        abort(ExitCode.BOTH_WAF_CERTS_IN_USE)
    elif waf_cert_a.is_active:
        active_waf_cert = waf_cert_a
        standby_waf_cert = waf_cert_b
    else:
        active_waf_cert = waf_cert_b
        standby_waf_cert = waf_cert_a

    if not is_update_needed(active_waf_cert, local_cert):
        logging.info("Active WAF cert is the same as local cert")
        logging.info("No action is needed. Bye.")
        exit(0)

    if standby_waf_cert.content != local_cert.content:
        logging.info("Updating WAF certificate %s...", standby_waf_cert.name)

        update_waf_certificate(
            waf_client=waf_client,
            current_waf_certificate=standby_waf_cert,
            new_certificate=local_cert)

    else:
        logging.warning(
            "Standby cert is already updated, maybe switchover failed before")

    switchover_waf_certificates(waf_client, active_waf_cert, standby_waf_cert)

    logging.info("Update and switchover performed successfully")


if __name__ == "__main__":
    main()
