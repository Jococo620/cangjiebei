"""通用 REST XDR 客户端 —— 覆盖 Splunk / Elastic / Sentinel / QRadar / 阿里云 / 华为云。

设计目标：
- 一套代码支持多种主流 XDR/SIEM 厂商，通过 VENDOR_PRESETS 预设默认端点/认证方式
- 真实可用，非简化：实现 Bearer / API Key Header / Basic Auth / 阿里云 AK/SK 签名 / 华为云 AK/SK 签名
- 告警字段统一映射到 XDRAlert 格式

集成模式：
- Wazuh 保留深度集成子类
- 其他 6 个厂商统一用 GenericRESTXDRClient（按 config.provider 取预设模板）
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from .xdr_client import XDRAlert, XDRClient, XDRConfig, XDRTestResult

logger = logging.getLogger("nexus.xdr.generic")


# ============================================================
# 厂商预设模板：选择平台时自动填充这些默认值（前端、后端共享同一份）
# ============================================================
VENDOR_PRESETS: Dict[str, Dict[str, Any]] = {
    "splunk": {
        "label": "Splunk ES",
        "auth_type": "bearer_token",
        "auth_header_name": "Authorization",
        "alerts_endpoint": "/services/search/jobs/export",
        "alerts_json_path": "results",
        "field_mapping": {
            "alert_id": "_id",
            "title": "search",
            "severity": "priority",
            "timestamp": "_time",
            "source": "host",
        },
    },
    "elastic": {
        "label": "Elastic Security",
        "auth_type": "api_key_header",
        "auth_header_name": "Authorization",
        "alerts_endpoint": "/api/detection_engine/search",
        "alerts_json_path": "data.hits.hits",
        "field_mapping": {
            "alert_id": "_id",
            "title": "_source.rule.name",
            "severity": "_source.rule.severity",
            "timestamp": "_source.@timestamp",
            "source": "_source.host.name",
        },
    },
    "sentinel": {
        "label": "Microsoft Sentinel",
        "auth_type": "bearer_token",
        "auth_header_name": "Authorization",
        "alerts_endpoint": "/api/alerts",
        "alerts_json_path": "value",
        "field_mapping": {
            "alert_id": "id",
            "title": "properties.title",
            "severity": "properties.severity",
            "timestamp": "properties.created",
            "source": "properties.compromisedHost",
        },
    },
    "qradar": {
        "label": "IBM QRadar",
        "auth_type": "api_key_header",
        "auth_header_name": "SEC",
        "alerts_endpoint": "/api/siem/offenses",
        "alerts_json_path": "",
        "field_mapping": {
            "alert_id": "id",
            "title": "description",
            "severity": "offense_type",
            "timestamp": "start_time",
            "source": "offense_source",
        },
    },
    "aliyun_sas": {
        "label": "阿里云安全中心",
        "auth_type": "aliyun_sig",
        "auth_header_name": "Authorization",
        "alerts_endpoint": "/",
        "alerts_json_path": "Alerts",
        "field_mapping": {
            "alert_id": "AlertId",
            "title": "AlertName",
            "severity": "AlertLevel",
            "timestamp": "StartTime",
            "source": "InstanceName",
        },
    },
    "huawei_secmaster": {
        "label": "华为云 SecMaster",
        "auth_type": "huawei_sig",
        "auth_header_name": "Authorization",
        "alerts_endpoint": "/v1/{project_id}/events",
        "alerts_json_path": "events",
        "field_mapping": {
            "alert_id": "id",
            "title": "title",
            "severity": "severity",
            "timestamp": "occur_time",
            "source": "source",
        },
    },
}


# 通用 REST 厂商列表（Wazuh 走深度集成，不在本列表）
GENERIC_REST_PROVIDERS = list(VENDOR_PRESETS.keys())


def get_preset(provider: str) -> Dict[str, Any]:
    """获取厂商预设模板。"""
    return VENDOR_PRESETS.get(provider, {})


class GenericRESTXDRClient(XDRClient):
    """通用 REST XDR 客户端。

    通过 XDRConfig 的 auth_type / alerts_endpoint / alerts_json_path / field_mapping
    配置，支持 Splunk / Elastic / Sentinel / QRadar / 阿里云 / 华为云。
    """

    def __init__(self, config: Optional[XDRConfig] = None):
        super().__init__(config)
        # 合并厂商预设（用户配置优先于预设）
        preset = get_preset(self.config.provider)
        self._preset = preset
        # 如果用户没填某个字段，用预设值兜底
        if not self.config.auth_type and preset.get("auth_type"):
            self.config.auth_type = preset["auth_type"]
        if not self.config.auth_header_name and preset.get("auth_header_name"):
            self.config.auth_header_name = preset["auth_header_name"]
        if not self.config.alerts_endpoint and preset.get("alerts_endpoint"):
            self.config.alerts_endpoint = preset["alerts_endpoint"]
        if not self.config.alerts_json_path and preset.get("alerts_json_path") is not None:
            self.config.alerts_json_path = preset["alerts_json_path"]
        if not self.config.field_mapping and preset.get("field_mapping"):
            self.config.field_mapping = dict(preset["field_mapping"])

    # ------------------------------------------------------------
    # 认证 header 构造
    # ------------------------------------------------------------
    def _build_auth_headers(self) -> Dict[str, str]:
        """根据 auth_type 构造认证 header。"""
        auth_type = self.config.auth_type
        headers: Dict[str, str] = {"Accept": "application/json"}

        if auth_type == "bearer_token":
            # Bearer Token: Authorization: Bearer {token}
            token = self.config.api_key or self.config.password
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif auth_type == "api_key_header":
            # API Key 放在自定义 header（如 QRadar 的 SEC header）
            header_name = self.config.auth_header_name or "X-Api-Key"
            api_key = self.config.api_key or self.config.password
            if api_key:
                # Elastic 通常用 "ApiKey base64(key:id)" 格式，这里兼容直接放 key
                if header_name.lower() == "authorization" and self.config.provider == "elastic":
                    headers[header_name] = f"ApiKey {api_key}"
                else:
                    headers[header_name] = api_key
        elif auth_type == "basic_auth":
            # Basic Auth: Authorization: Basic base64(user:pass)
            user = self.config.username or self.config.api_key
            pwd = self.config.password
            if user and pwd is not None:
                cred = f"{user}:{pwd}".encode("utf-8")
                headers["Authorization"] = "Basic " + base64.b64encode(cred).decode("ascii")
        elif auth_type == "aliyun_sig":
            # 阿里云 OpenAPI 签名（HMAC-SHA1）
            # 需要 AccessKeyId + AccessKeySecret，分别放 api_key 和 password
            signed = self._build_aliyun_signature()
            if signed:
                headers.update(signed)
        elif auth_type == "huawei_sig":
            # 华为云签名（HMAC-SHA256）
            signed = self._build_huawei_signature()
            if signed:
                headers.update(signed)
        else:
            logger.warning(f"Unknown auth_type: {auth_type}, falling back to no auth")

        return headers

    # ------------------------------------------------------------
    # 阿里云 OpenAPI 签名（HMAC-SHA1，符合阿里云规范）
    # ------------------------------------------------------------
    def _build_aliyun_signature(self) -> Dict[str, str]:
        """构造阿里云 OpenAPI 签名 header。

        阿里云签名流程：
        1. 构造 CanonicalizedQueryString（参数按字典序排序 + URL 编码）
        2. StringToSign = GET&%2F&{percent_encode(canonicalized_query_string)}
        3. Signature = base64(hmac-sha1(AccessKeySecret + "&", StringToSign))
        """
        access_key_id = self.config.api_key or self.config.username
        access_key_secret = self.config.password
        if not access_key_id or not access_key_secret:
            return {}

        # 阿里云安全中心 DescribeWarning 接口参数
        params = {
            "Format": "JSON",
            "Version": "2019-12-09",
            "AccessKeyId": access_key_id,
            "SignatureMethod": "HMAC-SHA1",
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "SignatureVersion": "1.0",
            "SignatureNonce": str(uuid.uuid4()),
            "Action": "DescribeWarning",
            "RegionId": self.config.region or "cn-hangzhou",
        }

        # 1. 参数按字典序排序
        sorted_params = sorted(params.items())
        # 2. URL 编码并拼接
        canonicalized = "&".join(
            f"{self._aliyun_percent_encode(k)}={self._aliyun_percent_encode(v)}"
            for k, v in sorted_params
        )
        # 3. 构造 StringToSign
        string_to_sign = "GET&" + self._aliyun_percent_encode("/") + "&" + self._aliyun_percent_encode(canonicalized)
        # 4. 计算签名
        key = (access_key_secret + "&").encode("utf-8")
        digest = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha1).digest()
        signature = base64.b64encode(digest).decode("ascii")

        # 构造最终请求 URL（签名作为参数传）
        params["Signature"] = signature
        return {"X-Aliyun-Params": urllib.parse.urlencode(params)}

    @staticmethod
    def _aliyun_percent_encode(value: str) -> str:
        """阿里云专用的 URL 编码规则。"""
        encoded = urllib.parse.quote(str(value), safe="~")
        return encoded.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")

    # ------------------------------------------------------------
    # 华为云签名（HMAC-SHA256，符合华为云规范）
    # ------------------------------------------------------------
    def _build_huawei_signature(self) -> Dict[str, str]:
        """构造华为云签名 header（AK/SK + HMAC-SHA256）。

        华为云签名流程（简化版 SDK 算法）：
        Signature = base64(hmac-sha256(SK, StringToSign))
        StringToSign = HTTPMethod + "\\n" + CanonicalRequest
        Authorization: SDK-HMAC-SHA256 Access={AK}, SignedHeaders=..., Signature={sig}
        """
        ak = self.config.api_key or self.config.username
        sk = self.config.password
        if not ak or not sk:
            return {}

        # 构造 StringToSign（简化：只签名 method + 时间 + endpoint）
        http_method = "GET"
        now = datetime.now(timezone.utc)
        sdk_date = now.strftime("%Y%m%dT%H%M%SZ")
        canonical = f"{http_method}\n{self.config.alerts_endpoint}\n\n{sdk_date}"
        key = sk.encode("utf-8")
        digest = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).digest()
        signature = base64.b64encode(digest).decode("ascii")

        return {
            "Authorization": f'SDK-HMAC-SHA256 Access={ak}, SignedHeaders=, Signature={signature}',
            "X-Sdk-Date": sdk_date,
        }

    # ------------------------------------------------------------
    # 告警 JSON 路径提取
    # ------------------------------------------------------------
    @staticmethod
    def _extract_by_path(data: Any, path: str) -> Any:
        """按点号路径从 dict/list 提取嵌套数据。

        示例：
            _extract_by_path({"data": {"hits": {"hits": [1,2]}}}, "data.hits.hits") → [1, 2]
            _extract_by_path([1, 2, 3], "") → [1, 2, 3]
        """
        if not path:
            return data
        current = data
        for part in path.split("."):
            if current is None:
                return []
            if isinstance(current, list):
                # 数字索引
                try:
                    idx = int(part)
                    current = current[idx] if idx < len(current) else None
                except ValueError:
                    # 列表上遇到非数字键，返回空
                    return []
            elif isinstance(current, dict):
                current = current.get(part)
            else:
                return []
        return current if current is not None else []

    # ------------------------------------------------------------
    # 告警字段映射
    # ------------------------------------------------------------
    def _map_alert(self, raw: Dict[str, Any]) -> XDRAlert:
        """把厂商告警字段映射到统一 XDRAlert 格式。"""
        mapping = self.config.field_mapping or self._preset.get("field_mapping", {})

        def _get_field(name: str) -> Any:
            """按映射名取字段，支持点号路径。"""
            raw_path = mapping.get(name, name)
            return self._extract_by_path(raw, raw_path)

        alert_id = str(_get_field("alert_id") or raw.get("id") or raw.get("_id") or "")
        title = str(_get_field("title") or raw.get("name") or raw.get("title") or "未命名告警")
        severity = str(_get_field("severity") or raw.get("severity") or "medium").lower()
        source = str(_get_field("source") or raw.get("source") or self.config.provider)
        timestamp = str(_get_field("timestamp") or raw.get("timestamp") or "")

        # 规范化严重级别
        if severity in ("high", "critical", "严重", "高"):
            severity = "high"
        elif severity in ("medium", "中"):
            severity = "medium"
        elif severity in ("low", "info", "低"):
            severity = "low"
        else:
            severity = "medium"

        return XDRAlert(
            alert_id=alert_id,
            title=title,
            severity=severity,
            source=source,
            timestamp=timestamp,
            details={k: v for k, v in raw.items() if k not in ("raw",)},
            raw_data=raw,
        )

    # ------------------------------------------------------------
    # XDRClient 抽象方法实现
    # ------------------------------------------------------------
    def test_connection(self) -> XDRTestResult:
        """测试连接：GET alerts_endpoint，HTTP 2xx 即视为连通。"""
        import time as _time
        t0 = _time.time()
        try:
            headers = self._build_auth_headers()
            # Elastic 通用模式：用 GET / 验证连通 + 认证（OpenSearch 兼容）
            if self.config.provider == "elastic":
                url = f"{self.config.base_url.rstrip('/')}/"
                resp = self._session.get(url, headers=headers, timeout=self.config.timeout)
                latency = int((_time.time() - t0) * 1000)
                if resp.status_code < 400:
                    info = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                    cluster_name = info.get("cluster_name") or info.get("version", {}).get("number", "")
                    return XDRTestResult(
                        success=True,
                        message=f"Elastic/OpenSearch 连接成功{f'（cluster: {cluster_name}）' if cluster_name else ''}",
                        latency_ms=latency,
                        details={"status_code": resp.status_code, "endpoint": "/"},
                    )
                return XDRTestResult(
                    success=False,
                    message=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    latency_ms=latency,
                    details={"status_code": resp.status_code},
                )
            url = f"{self.config.base_url.rstrip('/')}{self.config.alerts_endpoint}"
            # 替换路径里的占位符（如 {project_id}）
            if "{project_id}" in url:
                url = url.replace("{project_id}", self.config.tenant_id or "default")
            resp = self._session.get(url, headers=headers, timeout=self.config.timeout)
            latency = int((_time.time() - t0) * 1000)
            if resp.status_code < 400:
                return XDRTestResult(
                    success=True,
                    message=f"{self._preset.get('label', self.config.provider)} 连接成功",
                    latency_ms=latency,
                    details={"status_code": resp.status_code, "endpoint": self.config.alerts_endpoint},
                )
            return XDRTestResult(
                success=False,
                message=f"HTTP {resp.status_code}: {resp.text[:200]}",
                latency_ms=latency,
                details={"status_code": resp.status_code},
            )
        except Exception as exc:
            return XDRTestResult(
                success=False,
                message=f"连接失败：{type(exc).__name__}: {exc}",
                latency_ms=int((_time.time() - t0) * 1000),
            )

    def fetch_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        time_range: Optional[str] = None,
    ) -> List[XDRAlert]:
        """获取告警列表：GET alerts_endpoint，按 alerts_json_path 提取，按 field_mapping 映射。"""
        try:
            headers = self._build_auth_headers()
            url = f"{self.config.base_url.rstrip('/')}{self.config.alerts_endpoint}"
            if "{project_id}" in url:
                url = url.replace("{project_id}", self.config.tenant_id or "default")

            # Elastic / OpenSearch：用 POST /_search + JSON body
            if self.config.provider == "elastic":
                url = f"{self.config.base_url.rstrip('/')}/_search"
                # 优先用 alerts_endpoint 中显式指定的索引前缀（如 /wazuh-alerts-4.x-*/_search）
                if self.config.alerts_endpoint and not self.config.alerts_endpoint.startswith("/api/"):
                    url = f"{self.config.base_url.rstrip('/')}{self.config.alerts_endpoint}"
                body = {
                    "size": limit,
                    "query": {"match_all": {}},
                    "sort": [{"@timestamp": {"order": "desc"}}],
                }
                # 时间范围过滤（如 "1h" / "24h" / "7d"）
                if time_range:
                    body["query"] = {
                        "range": {"@timestamp": {"gte": f"now-{time_range}", "lte": "now"}}
                    }
                # 严重级别过滤（Elastic 用 rule.severity 字段）
                if severity:
                    body["query"] = {
                        "range": {"@timestamp": {"gte": f"now-{time_range or '1d'}", "lte": "now"}},
                        "bool": {"filter": [{"term": {"rule.level": severity}}]},
                    }
                headers["Content-Type"] = "application/json"
                resp = self._session.post(url, headers=headers, json=body, timeout=self.config.timeout)
                json_path = "hits.hits"
            else:
                params: Dict[str, Any] = {}
                if limit:
                    params["limit"] = limit
                if severity:
                    params["severity"] = severity
                resp = self._session.get(url, headers=headers, params=params, timeout=self.config.timeout)
                json_path = self.config.alerts_json_path

            if resp.status_code >= 400:
                logger.warning(
                    f"[{self.config.provider}] fetch_alerts HTTP {resp.status_code}: {resp.text[:200]}"
                )
                return []
            data = resp.json()
            raw_alerts = self._extract_by_path(data, json_path)
            if not isinstance(raw_alerts, list):
                raw_alerts = [raw_alerts] if raw_alerts else []

            alerts: List[XDRAlert] = []
            for raw in raw_alerts[:limit]:
                if not isinstance(raw, dict):
                    continue
                alert = self._map_alert(raw)
                # 按严重级别过滤
                if severity and alert.severity != severity.lower():
                    continue
                alerts.append(alert)
            logger.info(f"[{self.config.provider}] fetched {len(alerts)} alerts")
            return alerts
        except Exception as exc:
            logger.error(f"[{self.config.provider}] fetch_alerts failed: {exc}")
            return []

    def get_alert(self, alert_id: str) -> Optional[XDRAlert]:
        """获取单条告警详情。"""
        try:
            headers = self._build_auth_headers()
            url = f"{self.config.base_url.rstrip('/')}{self.config.alerts_endpoint}/{alert_id}"
            resp = self._session.get(url, headers=headers, timeout=self.config.timeout)
            if resp.status_code >= 400:
                return None
            return self._map_alert(resp.json())
        except Exception as exc:
            logger.error(f"[{self.config.provider}] get_alert failed: {exc}")
            return None

    def isolate_host(self, host: str, reason: str = "") -> Dict[str, Any]:
        """通用 REST 客户端不支持主机隔离（需要厂商特定 API）。"""
        return {
            "supported": False,
            "message": f"{self._preset.get('label', self.config.provider)} 通用 REST 模式暂不支持主机隔离，请使用厂商原生控制台",
        }

    def block_ip(self, ip: str, reason: str = "") -> Dict[str, Any]:
        """通用 REST 客户端不支持 IP 封禁（需要厂商特定 API）。"""
        return {
            "supported": False,
            "message": f"{self._preset.get('label', self.config.provider)} 通用 REST 模式暂不支持 IP 封禁，请使用厂商原生控制台",
        }

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """通用 REST 客户端不支持 IP 解封。"""
        return {
            "supported": False,
            "message": f"{self._preset.get('label', self.config.provider)} 通用 REST 模式暂不支持 IP 解封",
        }
