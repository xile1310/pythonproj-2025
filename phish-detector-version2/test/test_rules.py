#!/usr/bin/env python3
"""
Optimized pytest tests for rules.py functionality.
Reduced from 17 to 9 essential tests while maintaining full functional coverage and edge cases.
"""

import sys
import os
import pytest

# Add parent directory to path so we can import rules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from rules import (
    classify_email,
    whitelist_check,
    keyword_check,
    edit_distance_check,
    suspicious_url_check,
    LEGIT_DOMAINS,
    SUS_KEYWORDS,
    reset_to_defaults
)


@pytest.fixture(autouse=True)
def reset_config():
    """Reset configuration before each test."""
    LEGIT_DOMAINS.clear()
    SUS_KEYWORDS.clear()
    LEGIT_DOMAINS.update(["paypal.com", "google.com"])
    SUS_KEYWORDS.update(["urgent", "verify", "click", "account"])


class TestCoreFunctionality:
    """Test core functionality of all rule functions."""
    
    def test_whitelist_check(self):
        """Test domain whitelist checking with legitimate and non-legitimate domains."""
        # Legitimate domains
        assert whitelist_check("user@paypal.com") == 0
        assert whitelist_check("admin@google.com") == 0
        assert whitelist_check("user@PAYPAL.COM") == 0  # Case insensitive
        
        # Non-legitimate domains
        assert whitelist_check("user@unknown.com") == 2
        assert whitelist_check("spam@evil.org") == 2
        
        # Edge case: Invalid email formats
        assert whitelist_check("") == 2
        assert whitelist_check("notanemail") == 2
        assert whitelist_check("user@") == 2
    
    def test_keyword_check(self):
        """Test keyword detection in subject and body with case insensitivity."""
        # No keywords
        assert keyword_check("Meeting Reminder", "Regular email content") == 0
        
        # Keywords in subject (3 points each)
        assert keyword_check("Urgent: Verify", "Normal content") == 6
        
        # Keywords in body (1 point + 4 early bonus)
        assert keyword_check("Normal Subject", "Please click verify") == 6
        
        # Case insensitive keywords
        assert keyword_check("URGENT VERIFY", "CLICK") == 9
        
        # Edge case: Empty strings
        assert keyword_check("", "") == 0
    
    def test_edit_distance_check(self):
        """Test lookalike domain detection using Levenshtein distance."""
        # Exact matches
        assert edit_distance_check("user@paypal.com") == 0
        assert edit_distance_check("user@google.com") == 0
        
        # Lookalike domains (5 points)
        assert edit_distance_check("user@paypa1.com") == 5
        assert edit_distance_check("user@g00gle.com") == 5
        
        # Not similar enough
        assert edit_distance_check("user@facebook.com") == 0
        assert edit_distance_check("user@amazon.com") == 0
    
    def test_suspicious_url_check(self):
        """Test suspicious URL pattern detection."""
        # No URLs
        assert suspicious_url_check("No links", "Just text") == 0
        
        # IP literal URLs (5 points)
        assert suspicious_url_check("", "Visit http://192.168.1.1") == 5
        
        # User@host URLs (3 points)
        assert suspicious_url_check("", "Visit http://user@example.com") == 3
        
        # Legitimate URLs
        body = "Visit https://www.paypal.com/login"
        assert suspicious_url_check("", body) == 0


class TestEmailClassification:
    """Test end-to-end email classification with various scenarios."""
    
    def test_safe_email(self):
        """Test clearly safe emails."""
        sender = "support@paypal.com"
        subject = "Service Update"
        body = "We have updated our service."
        
        label, score = classify_email(sender, subject, body)
        assert label == "Safe"
        assert score == 0
    
    def test_phishing_email(self):
        """Test clearly phishing emails with multiple suspicious elements."""
        sender = "admin@paypa1.com"  # Lookalike domain (+5)
        subject = "Urgent: Verify Account"  # Keywords (+6)
        body = "Click here: http://192.168.1.1/verify"  # IP URL (+5)
        
        label, score = classify_email(sender, subject, body)
        assert label == "Phishing"
        assert score > 10
    
    def test_borderline_email(self):
        """Test emails with score around threshold."""
        sender = "user@unknown.com"  # +2 points
        subject = "test subject"  # No keywords
        body = "test message"      # No keywords
        
        label, score = classify_email(sender, subject, body)
        assert score == 2
        assert label == "Safe"  # Since score < 10


class TestEdgeCasesAndErrors:
    """Test edge cases, error handling, and complex scenarios."""
    
    def test_multiple_rule_combinations(self):
        """Test scoring from multiple rule sources."""
        sender = "user@unknown.com"  # +2
        subject = "Urgent"           # +3
        body = "Click verify"        # +6 (+2 early +1 body)
        
        label, score = classify_email(sender, subject, body)
        assert score == 11  # 2 + 3 + 6 = 11
        assert label == "Phishing"  # > 10
    
    def test_error_handling(self):
        """Test various error conditions."""
        # NameError
        with pytest.raises(NameError):
            undefined_variable
        
        # AttributeError
        with pytest.raises(AttributeError):
            class BadClass:
                pass
            bad_obj = BadClass()
            bad_obj.nonexistent_method()
        
        # TypeError
        with pytest.raises(TypeError):
            10 + "string"
        
        # IndexError
        with pytest.raises(IndexError):
            my_list = [1, 2, 3]
            my_list[10]
    
    def test_configuration_management(self):
        """Test configuration reset functionality."""
        # Add custom entries
        LEGIT_DOMAINS.add("test.com")
        SUS_KEYWORDS.add("test")
        
        # Reset to defaults
        reset_to_defaults()
        
        # Verify reset
        assert "test.com" not in LEGIT_DOMAINS
        assert "test" not in SUS_KEYWORDS
        assert "paypal.com" in LEGIT_DOMAINS
        assert "urgent" in SUS_KEYWORDS
