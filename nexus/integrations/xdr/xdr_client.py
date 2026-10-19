"""XDR 客户端抽象基类。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests


@dataclass
class XDRConfig:
    """XDR 连接配置。

    Wazuh：username/password + (可选) indexer_url/indexer_user/indexer_password
    通用 REST 厂商（Splunk/Elastic/Sentinel/QRadar/阿里云/华为云）：
        auth_type + alerts_endpoint + alerts_json_path + field_mapping 等
    """

    provider: str = ""
    base_url: str = ""
    api_key: str = ""
    username: str = ""
    password: str = ""
    verify_ssl: bool = True
    timeout: int = 30
    # Wazuh Indexer (OpenSearch) 独立连接信息
    indexer_url: str = ""
    indexer_user: str = ""
    indexer_password: str = ""
    # 通用 REST 客户端字段（Splunk/Elastic/Sentinel/QRadar/阿里云/华为云）
    auth_type: str = ""              # api_key_header | bearer_token | basic_auth | aliyun_sig | huawei_sig
    auth_header_name: str = ""       # API Key 放在哪个 header（如 "Authorization" / "SEC"）
    alerts_endpoint: str = ""       # 告警查询端点路径
    alerts_json_path: str = ""      # 告警列表在响应中的 JSON 路径（如 "results" / "data.hits.hits"）
    field_mapping: Dict[str, str] = field(default_factory=dict)  # 厂商字段 → 统一字段映射
    tenant_id: str = ""             # Azure 租户 ID（Sentinel 用）
    token_url: str = ""             # OAuth token 端点（Sentinel 用）
    region: str = ""                # 云厂商区域（阿里云/华为云用）
    # 客户端扩展存储 (get_xdr_client 初始化时注入)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "username": self.username,
            "indexer_url": self.indexer_url,
            "indexer_user": self.indexer_user,
            "verify_ssl": self.verify_ssl,
            "timeout": self.timeout,
            "api_key_set": bool(self.api_key),
            "credentials_set": bool(self.username and self.password),
            "indexer_password_set": bool(self.indexer_password),
            # 通用 REST 字段（非敏感，明文返回）
            "auth_type": self.auth_type,
            "auth_header_name": self.auth_header_name,
            "alerts_endpoint": self.alerts_endpoint,
            "alerts_json_path": self.alerts_json_path,
            "field_mapping": self.field_mapping,
            "tenant_id": self.tenant_id,
            "token_url": self.token_url,
            "region": self.region,
        }


@dataclass
class XDRAlert:
    """XDR 告警数据。"""

    alert_id: str = ""
    title: str = ""
    severity: str = ""
    source: str = ""
    timestamp: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class XDRTestResult:
    """XDR 连接测试结果。"""

    success: bool = False
    message: str = ""
    latency_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


class XDRClient(ABC):
    """XDR 客户端抽象基类。"""

    def __init__(self, config: Optional[XDRConfig] = None):
        self.config = config or XDRConfig()
        self._session = requests.Session()
        self._session.verify = self.config.verify_ssl

    @abstractmethod
    def test_connection(self) -> XDRTestResult:
        """测试连接 XDR 平台。"""
        ...

    @abstractmethod
    def fetch_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        time_range: Optional[str] = None,
    ) -> List[XDRAlert]:
        """获取告警列表。"""
        ...

    @abstractmethod
    def get_alert(self, alert_id: str) -> Optional[XDRAlert]:
        """获取单条告警详情。"""
        ...

    @abstractmethod
    def isolate_host(self, host: str, reason: str = "") -> Dict[str, Any]:
        """隔离主机。"""
        ...

    @abstractmethod
    def block_ip(self, ip: str, reason: str = "") -> Dict[str, Any]:
        """封禁 IP。"""
        ...

    @abstractmethod
    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """解封 IP。"""
        ...

    @property
    def provider_name(self) -> str:
        """提供商名称。"""
        return self.config.provider

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """发送 HTTP 请求。"""
        url = f"{self.config.base_url.rstrip('/')}{endpoint}"
        return self._session.request(
            method=method,
            url=url,
            params=params,
            json=data,
            headers=headers or {},
            timeout=self.config.timeout,
        )

    def close(self) -> None:
        """关闭连接。"""
        self._session.close()
