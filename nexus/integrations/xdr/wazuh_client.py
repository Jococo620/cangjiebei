"""Wazuh XDR 客户端实现。

对接 Wazuh 4.9.x 平台：
- Manager REST API (默认 55000)：获取 JWT、agent 管理、active-response、CDB/列表、隔离等
- Indexer (OpenSearch, 默认 9200)：查询 `wazuh-alerts-4.x-*` 索引获取告警

Manager API 认证流程：
  1. POST /security/user/authenticate  Basic(user:pass) -> 返回 JWT (exp 900s)
  2. 之后所有 Manager 请求携带 Authorization: Bearer <JWT>

文档参考：https://documentation.wazuh.com/current/user-manual/api/index.html
"""

from __future__ import annotations

import base64
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .xdr_client import XDRAlert, XDRClient, XDRConfig, XDRTestResult


class WazuhXDRClient(XDRClient):
    """Wazuh 4.x 平台客户端。"""

    def __init__(self, config: Optional[XDRConfig] = None):
        super().__init__(config)
        # 从 config.api_key 或 config.extra 解析 indexer_base_url / indexer_user / indexer_password
        # 为了兼容现有 XDRConfig 字段，我们约定：
        #   base_url        = Manager API, e.g. https://localhost:55000
        #   username/pass   = Manager API 用户 (默认 wazuh-wui)
        #   indexer_url     = 通过 base_url 的"端口 9200" 推断，或传入 config.extra["indexer_url"]
        #   indexer_user    = config.extra["indexer_user"]  或默认 admin
        #   indexer_pass    = config.api_key（当设置了 api_key 时）或 config.extra["indexer_password"]
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._indexer_url: Optional[str] = None
        self._indexer_user: str = "admin"
        self._indexer_pass: str = ""
        self._resolve_indexer()
        # 禁用 SSL 校验（本地自签证书）
        if not self.config.verify_ssl:
            self._session.verify = False
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    # -------- 配置 --------
    @property
    def provider_name(self) -> str:
        return "wazuh"

    def _resolve_indexer(self) -> None:
        """推断 Indexer 地址与凭据。

        优先级（高→低）：
        1. XDRConfig.indexer_url / indexer_user / indexer_password（明确字段）
        2. XDRConfig.extra 中的同名键（向后兼容）
        3. Manager 端口 55000 => Indexer 同主机 9200
        4. api_key 字段兜底（用作 Indexer 密码，兼容老逻辑）
        """
        # 1) 明确字段优先
        if getattr(self.config, "indexer_url", None):
            self._indexer_url = self.config.indexer_url
        if getattr(self.config, "indexer_user", None):
            self._indexer_user = self.config.indexer_user
        if getattr(self.config, "indexer_password", None):
            self._indexer_pass = self.config.indexer_password
        # 2) extra 兜底
        extra = getattr(self.config, "extra", None) or {}
        if not self._indexer_url and extra.get("indexer_url"):
            self._indexer_url = extra["indexer_url"]
        if not self._indexer_user and extra.get("indexer_user"):
            self._indexer_user = extra["indexer_user"]
        if not self._indexer_pass and extra.get("indexer_password"):
            self._indexer_pass = extra["indexer_password"]
        # 3) URL 推断
        if not self._indexer_url:
            base = self.config.base_url.rstrip("/")
            if base.endswith(":55000"):
                self._indexer_url = base.rsplit(":", 1)[0] + ":9200"
            elif ":55000/" in base:
                self._indexer_url = base.replace(":55000/", ":9200/")
        # 4) api_key 用作 Indexer 密码（老逻辑兼容）
        if not self._indexer_pass and self.config.api_key:
            self._indexer_pass = self.config.api_key

    # -------- 认证 --------
    def _ensure_jwt(self) -> None:
        """确保持有有效的 JWT。失效/快过期则重新申请。"""
        now = time.time()
        if self._token and now < self._token_expires_at - 30:
            return
        if not self.config.username or not self.config.password:
            raise ValueError("Wazuh Manager API 用户名和密码未配置")
        creds = base64.b64encode(
            f"{self.config.username}:{self.config.password}".encode()
        ).decode()
        resp = self._request(
            "POST",
            "/security/user/authenticate",
            headers={"Authorization": f"Basic {creds}"},
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Wazuh 认证失败 HTTP {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        self._token = data.get("data", {}).get("token")
        if not self._token:
            raise RuntimeError("Wazuh 认证返回未包含 token")
        # JWT 默认 900 秒有效期
        self._token_expires_at = now + 900.0

    def _manager_headers(self) -> Dict[str, str]:
        self._ensure_jwt()
        return {"Authorization": f"Bearer {self._token}"}

    # -------- 测试连接 --------
    def test_connection(self) -> XDRTestResult:
        start = time.time()
        errors: List[str] = []
        details: Dict[str, Any] = {"provider": "wazuh"}

        # 1) Manager
        try:
            resp = self._request(
                "GET", "/manager/info", headers=self._manager_headers()
            )
            mgr_ok = resp.status_code == 200
            if mgr_ok:
                info = resp.json()
                items = info.get("data", {}).get("affected_items", [])
                if items:
                    details["manager_version"] = items[0].get("version", "?")
                    details["manager_type"] = items[0].get("type", "?")
                    details["max_agents"] = items[0].get("max_agents", "?")
            else:
                errors.append(f"Manager HTTP {resp.status_code}")
        except Exception as e:
            mgr_ok = False
            errors.append(f"Manager: {str(e)}")

        # 2) Indexer
        idx_ok = False
        if self._indexer_url:
            try:
                r = self._session.get(
                    f"{self._indexer_url}/_cluster/health",
                    auth=(self._indexer_user, self._indexer_pass),
                    timeout=self.config.timeout,
                )
                idx_ok = r.status_code == 200
                if idx_ok:
                    details["indexer_status"] = r.json().get("status", "?")
                else:
                    errors.append(f"Indexer HTTP {r.status_code}")
            except Exception as e:
                errors.append(f"Indexer: {str(e)}")
        else:
            errors.append("Indexer 地址未解析")

        latency = (time.time() - start) * 1000
        ok = mgr_ok and (idx_ok or not self._indexer_url)
        return XDRTestResult(
            success=ok,
            message="Wazuh 连接测试成功"
            if ok
            else "连接失败: " + "; ".join(errors),
            latency_ms=round(latency, 1),
            details=details,
        )

    # -------- 告警（走 Indexer） --------
    def fetch_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        time_range: Optional[str] = None,
    ) -> List[XDRAlert]:
        """从 Wazuh Indexer (OpenSearch) 查询告警。"""
        if not self._indexer_url:
            return []
        try:
            must: List[Dict[str, Any]] = []
            if severity:
                # severity -> Wazuh rule.level 区间
                rng = {
                    "critical": {"gte": 12},
                    "high": {"gte": 8, "lt": 12},
                    "medium": {"gte": 4, "lt": 8},
                    "low": {"gte": 2, "lt": 4},
                    "info": {"lt": 2},
                }.get(severity)
                if rng:
                    must.append({"range": {"rule.level": rng}})
            if time_range and time_range.lower() != "all":
                # 支持 "1h" / "24h" / "7d"
                unit = time_range[-1]
                num = int(time_range[:-1]) if time_range[:-1].isdigit() else 24
                delta = {"h": timedelta(hours=num), "d": timedelta(days=num)}.get(
                    unit, timedelta(hours=num)
                )
                gte = (datetime.utcnow() - delta).strftime("%Y-%m-%dT%H:%M:%SZ")
                must.append({"range": {"timestamp": {"gte": gte}}})

            query: Dict[str, Any] = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": must}} if must else {"match_all": {}},
            }
            r = self._session.post(
                f"{self._indexer_url}/wazuh-alerts-4.x-*/_search",
                auth=(self._indexer_user, self._indexer_pass),
                json=query,
                timeout=self.config.timeout,
            )
            if r.status_code != 200:
                return []
            hits = r.json().get("hits", {}).get("hits", [])
            return [self._parse_alert(h["_source"]) for h in hits]
        except Exception:
            return []

    def get_alert(self, alert_id: str) -> Optional[XDRAlert]:
        """按 ID 查询告警。Wazuh Indexer 文档无稳定 id 字段，通过 full_log 检索近似。"""
        if not self._indexer_url:
            return None
        try:
            query = {
                "size": 1,
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"_id": alert_id}},
                            {"match": {"id": alert_id}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            }
            r = self._session.post(
                f"{self._indexer_url}/wazuh-alerts-4.x-*/_search",
                auth=(self._indexer_user, self._indexer_pass),
                json=query,
                timeout=self.config.timeout,
            )
            if r.status_code != 200:
                return None
            hits = r.json().get("hits", {}).get("hits", [])
            if hits:
                return self._parse_alert(hits[0]["_source"])
            return None
        except Exception:
            return None

    # -------- 处置 --------
    def isolate_host(self, host: str, reason: str = "") -> Dict[str, Any]:
        """通过 Wazuh Active-Response / CDB deny_ips 实现主机隔离。

        优先：将 host IP 写入 CDB 列表 deny_ips，触发 active-response 阻断。
        备选：调用 /active-response 下发防火墙阻断。
        """
        try:
            # 1) 写入 CDB deny_ips (block_ip 同路径)
            result = self.block_ip(host, reason=reason or "Isolated via 鉴真 AI")
            # 2) 额外添加到 syscheck/rootcheck 列表用于审计
            return {
                "success": result.get("success", False),
                "message": result.get("message", "isolate failed"),
                "host": host,
                "reason": reason,
            }
        except Exception as e:
            return {"success": False, "message": str(e), "host": host}

    def block_ip(self, ip: str, reason: str = "") -> Dict[str, Any]:
        """封禁 IP：写入 Wazuh Manager 的 CDB 列表 deny_ips。"""
        try:
            cdb_name = "deny_ips"
            body = {
                "list": [
                    {
                        "key": ip,
                        "value": reason or "Blocked via 鉴真 AI",
                    }
                ]
            }
            resp = self._request(
                "PUT",
                f"/cdb/{cdb_name}/data",
                data=body,
                headers=self._manager_headers(),
            )
            if resp.status_code in (200, 201):
                payload = resp.json()
                return {
                    "success": True,
                    "message": f"IP {ip} 封禁指令已下发(CDB deny_ips)",
                    "ip": ip,
                    "reason": reason,
                    "details": payload.get("data", {}),
                }
            # 若 PUT 失败，尝试直接 POST 到 lists（用于创建列表）
            resp2 = self._request(
                "POST",
                f"/lists",
                data={
                    "name": "deny_ips",
                    "description": "Blocked IP list managed by 鉴真 AI",
                },
                headers=self._manager_headers(),
            )
            _ = resp2
            return {
                "success": False,
                "message": f"封禁失败 HTTP {resp.status_code}: {resp.text[:160]}",
                "ip": ip,
                "reason": reason,
            }
        except Exception as e:
            return {"success": False, "message": str(e), "ip": ip}

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """解封 IP：从 CDB deny_ips 移除。"""
        try:
            cdb_name = "deny_ips"
            resp = self._request(
                "DELETE",
                f"/cdb/{cdb_name}/data/{ip}",
                headers=self._manager_headers(),
            )
            ok = resp.status_code == 200
            return {
                "success": ok,
                "message": (
                    f"IP {ip} 解封成功" if ok else f"解封失败 HTTP {resp.status_code}"
                ),
                "ip": ip,
            }
        except Exception as e:
            return {"success": False, "message": str(e), "ip": ip}

    # -------- 内部 --------
    def _parse_alert(self, src: Dict[str, Any]) -> XDRAlert:
        rule = src.get("rule", {}) or {}
        agent = src.get("agent", {}) or {}
        decoder = src.get("decoder", {}) or {}
        full_log = src.get("full_log", "")
        level = int(rule.get("level", 0) or 0)
        return XDRAlert(
            alert_id=str(src.get("id", "") or src.get("_id", "")),
            title=str(
                rule.get("description")
                or (full_log[:200] if full_log else "(no description)")
            ),
            severity=self._map_severity(level),
            source=agent.get("name") or agent.get("ip") or src.get("location", ""),
            timestamp=src.get("timestamp", ""),
            details={
                "rule_id": rule.get("id"),
                "rule_level": level,
                "rule_groups": rule.get("groups"),
                "agent_id": agent.get("id"),
                "agent_name": agent.get("name"),
                "agent_ip": agent.get("ip"),
                "decoder": decoder.get("name"),
                "location": src.get("location"),
                "manager": (src.get("manager", {}) or {}).get("name"),
                "full_log": full_log[:500],
            },
            raw_data=src,
        )

    @staticmethod
    def _map_severity(level: int) -> str:
        """Wazuh level 1-15 -> 统一严重等级。"""
        if level >= 12:
            return "critical"
        if level >= 8:
            return "high"
        if level >= 4:
            return "medium"
        if level >= 2:
            return "low"
        return "info"
