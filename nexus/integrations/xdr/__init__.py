"""XDR 平台集成模块。"""

from .xdr_client import XDRClient, XDRConfig, XDRAlert, XDRTestResult
from .wazuh_client import WazuhXDRClient
from .generic_rest_client import GenericRESTXDRClient, VENDOR_PRESETS, GENERIC_REST_PROVIDERS


# 全部支持的厂商（Wazuh 深度集成 + 其他通用 REST 厂商）
SUPPORTED_XDR_PROVIDERS = ["wazuh"] + GENERIC_REST_PROVIDERS


def get_xdr_client(provider: str, config: XDRConfig | None = None) -> XDRClient:
    """根据 provider 名称获取对应的 XDR 客户端。

    - wazuh：走深度集成子类
    - splunk / elastic / sentinel / qradar / aliyun_sas / huawei_secmaster：走 GenericRESTXDRClient
    """
    provider = provider.lower()
    if provider == "wazuh":
        return WazuhXDRClient(config)
    elif provider in GENERIC_REST_PROVIDERS:
        return GenericRESTXDRClient(config)
    else:
        raise ValueError(f"Unsupported XDR provider: {provider}")
