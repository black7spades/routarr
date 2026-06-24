"""
Core unit tests for Routarr.

Run with:  pytest tests/
"""

import time
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def test_hash_and_verify_correct_password():
    from main import _hash_pw, _verify_pw
    h = _hash_pw("correct-horse-battery-staple")
    assert _verify_pw("correct-horse-battery-staple", h)


def test_verify_wrong_password():
    from main import _hash_pw, _verify_pw
    h = _hash_pw("secret")
    assert not _verify_pw("wrong", h)


def test_verify_empty_stored_hash():
    from main import _verify_pw
    assert not _verify_pw("anything", "")


def test_two_hashes_of_same_password_differ():
    # Salted hashes: same password should produce different stored values
    from main import _hash_pw
    h1 = _hash_pw("password")
    h2 = _hash_pw("password")
    assert h1 != h2


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

def test_valid_url_http():
    from main import _valid_url
    assert _valid_url("http://192.168.1.10:32400")


def test_valid_url_https():
    from main import _valid_url
    assert _valid_url("https://plex.example.com")


def test_valid_url_empty_is_ok():
    # Empty means "not configured yet" — allowed
    from main import _valid_url
    assert _valid_url("")


def test_invalid_url_no_scheme():
    from main import _valid_url
    assert not _valid_url("192.168.1.10:32400")


def test_invalid_url_ftp():
    from main import _valid_url
    assert not _valid_url("ftp://192.168.1.10")


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

def test_rate_ok_within_limit():
    from main import _rate_ok, _rate_buckets
    _rate_buckets.clear()
    for _ in range(3):
        assert _rate_ok("1.2.3.4", "test_endpoint", max_calls=5, window=60)


def test_rate_ok_blocked_after_limit():
    from main import _rate_ok, _rate_buckets
    _rate_buckets.clear()
    for _ in range(5):
        _rate_ok("1.2.3.5", "test_ep2", max_calls=5, window=60)
    # 6th call should be blocked
    assert not _rate_ok("1.2.3.5", "test_ep2", max_calls=5, window=60)


def test_rate_ok_different_ips_independent():
    from main import _rate_ok, _rate_buckets
    _rate_buckets.clear()
    for _ in range(5):
        _rate_ok("10.0.0.1", "ep", max_calls=5, window=60)
    # Different IP should still be allowed
    assert _rate_ok("10.0.0.2", "ep", max_calls=5, window=60)


def test_rate_ok_window_expires():
    from main import _rate_ok, _rate_buckets
    _rate_buckets.clear()
    # Fill the bucket with timestamps just outside the window
    old_time = time.time() - 120
    _rate_buckets[("5.5.5.5", "exp")] = [old_time] * 5
    # Old entries are outside the 60s window — should be allowed
    assert _rate_ok("5.5.5.5", "exp", max_calls=5, window=60)


# ---------------------------------------------------------------------------
# Routing rule resolution
# ---------------------------------------------------------------------------

def test_resolve_channel_exact_genre_match():
    from main import resolve_channel
    rules = [{
        "section_id": "1", "label": "Comedy", "label_excl": "",
        "channel_id": "ch1", "channel_name": "Comedy Channel", "priority": 0,
    }]
    with patch("main.routing_rules", return_value=rules):
        result = resolve_channel("1", ["Comedy", "Drama"])
    assert result == ("ch1", "Comedy Channel")


def test_resolve_channel_no_match():
    from main import resolve_channel
    rules = [{
        "section_id": "1", "label": "Comedy", "label_excl": "",
        "channel_id": "ch1", "channel_name": "Comedy Channel", "priority": 0,
    }]
    with patch("main.routing_rules", return_value=rules):
        result = resolve_channel("1", ["Action"])
    assert result is None


def test_resolve_channel_catchall():
    from main import resolve_channel
    rules = [{
        "section_id": "1", "label": "", "label_excl": "",
        "channel_id": "ch_all", "channel_name": "Everything", "priority": 0,
    }]
    with patch("main.routing_rules", return_value=rules):
        result = resolve_channel("1", ["Anything"])
    assert result == ("ch_all", "Everything")


def test_resolve_channel_exclusion_blocks():
    from main import resolve_channel
    rules = [{
        "section_id": "1", "label": "", "label_excl": "Kids",
        "channel_id": "ch1", "channel_name": "Adults Only", "priority": 0,
    }]
    with patch("main.routing_rules", return_value=rules):
        result = resolve_channel("1", ["Comedy", "Kids"])
    assert result is None


def test_resolve_channel_higher_priority_wins():
    from main import resolve_channel
    rules = [
        # routing_rules() returns highest priority first
        {
            "section_id": "1", "label": "Comedy", "label_excl": "",
            "channel_id": "ch_high", "channel_name": "High Priority", "priority": 10,
        },
        {
            "section_id": "1", "label": "Comedy", "label_excl": "",
            "channel_id": "ch_low", "channel_name": "Low Priority", "priority": 0,
        },
    ]
    with patch("main.routing_rules", return_value=rules):
        result = resolve_channel("1", ["Comedy"])
    assert result == ("ch_high", "High Priority")


def test_resolve_channel_wrong_section():
    from main import resolve_channel
    rules = [{
        "section_id": "2", "label": "Comedy", "label_excl": "",
        "channel_id": "ch1", "channel_name": "Comedy Channel", "priority": 0,
    }]
    with patch("main.routing_rules", return_value=rules):
        result = resolve_channel("1", ["Comedy"])
    assert result is None


def test_resolve_channel_wildcard_section():
    from main import resolve_channel
    rules = [{
        "section_id": "*", "label": "Comedy", "label_excl": "",
        "channel_id": "ch_any", "channel_name": "Any Section Comedy", "priority": 0,
    }]
    with patch("main.routing_rules", return_value=rules):
        result = resolve_channel("99", ["Comedy"])
    assert result == ("ch_any", "Any Section Comedy")


def test_resolve_channel_multi_label_all_required():
    from main import resolve_channel
    rules = [{
        "section_id": "1", "label": "Comedy,Romance", "label_excl": "",
        "channel_id": "ch1", "channel_name": "Rom-Com", "priority": 0,
    }]
    with patch("main.routing_rules", return_value=rules):
        # Has both Comedy AND Romance — should match
        assert resolve_channel("1", ["Comedy", "Romance", "Drama"]) == ("ch1", "Rom-Com")
        # Has only Comedy — should NOT match (requires both)
        assert resolve_channel("1", ["Comedy"]) is None
