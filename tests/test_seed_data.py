"""seed_data 安全知识库种子与 STIX2 导出单元测试。"""

import pytest

from nexus.cang import seed_data


def test_seed_non_empty():
    assert len(seed_data.SECURITY_KB_SEED) >= 5


def test_seed_entries_have_required_fields():
    for item in seed_data.SECURITY_KB_SEED:
        assert item["id"]
        assert item["source"]
        assert item["title"]
        assert item["text"]


def test_seed_has_no_residual_branding():
    """去品牌化回归：知识库不应再残留任何原厂商/赛事痕迹。"""
    blob = str(seed_data.SECURITY_KB_SEED).lower()
    for banned in ("sangfor", "深信服", "sf_gpt", "挑战杯", "xh-2026", "superagent"):
        assert banned not in blob


def test_load_seed_returns_copy():
    items = seed_data.load_seed()
    assert items == seed_data.SECURITY_KB_SEED
    items[0]["id"] = "MUTATED"
    assert seed_data.SECURITY_KB_SEED[0]["id"] != "MUTATED"


def test_to_stix2_bundle():
    bundle = seed_data.to_stix2_bundle()
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == len(seed_data.SECURITY_KB_SEED)
    for obj in bundle["objects"]:
        assert obj["type"] in {"attack-pattern", "vulnerability", "indicator"}
        assert obj["spec_version"] == "2.1"


def test_stix_id_deterministic():
    a = seed_data._stix_id("vulnerability", "CWE-78")
    b = seed_data._stix_id("vulnerability", "CWE-78")
    assert a == b
    assert a.startswith("vulnerability--")


def test_misp_feed_importable():
    assert isinstance(seed_data.MISP_EXAMPLE_FEED, list)
    assert len(seed_data.MISP_EXAMPLE_FEED) >= 1
