#!/usr/bin/env python3
"""
Simple pytest tests for rules.py functionality.
Tests core rules and includes error cases for demonstration.
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


class TestWhitelistCheck:
    """Test whitelist checking functionality."""
    
    def test_legitimate_domain(self):
        """Test legitimate domains get 0 points."""
        assert whitelist_check("user@paypal.com") == 0
        assert whitelist_check("admin@google.com") == 0
    
    def test_non_legitimate_domain(self):
        """Test non-legitimate domains get 2 points."""
        assert whitelist_check("user@unknown.com") == 2
        assert whitelist_check("spam@evil.org") == 2
    
    def test_case_insensitive(self):
        """Test domain checking is case-insensitive."""
        assert whitelist_check("user@PAYPAL.COM") == 0
        assert whitelist_check("user@UNKNOWN.COM") == 2
    
    def test_error_invalid_email(self):
        """Test that invalid email formats are handled."""
        assert whitelist_check("") == 2  # Empty string
        assert whitelist_check("notanemail") == 2  # Missing @ and .
        assert whitelist_check("user@") == 2  # Missing domain


class TestKeywordCheck:
    """Test keyword checking functionality."""
    
    def test_no_keywords(self):
        """Test emails with no suspicious keywords."""
        assert keyword_check("Meeting Reminder", "Regular email content") == 0
    
    def test_keywords_in_subject(self):
        """Test keywords in subject get +3 points each."""
        assert keyword_check("Urgent: Verify", "Normal content") == 6  # urgent(+3) + verify(+3)
    
    def test_keywords_in_body(self):
        """Test keywords in body get points."""
        assert keyword_check("Normal Subject", "Please click verify") == 6  # click(+1) verify(+1) + early bonus(4)
    
    def test_case_insensitive_keywords(self):
        """Test keyword detection is case-insensitive."""
        assert keyword_check("URGENT VERIFY", "CLICK") == 9  # 3+3+3 = 9
    
    def test_error_empty_strings(self):
        """Test handling of empty strings."""
        assert keyword_check("", "") == 0


class TestEditDistanceCheck:
    """Test edit distance (lookalike domain) checking."""
    
    def test_exact_match(self):
        """Test exact domain matches get 0 points."""
        assert edit_distance_check("user@paypal.com") == 0
        assert edit_distance_check("user@google.com") == 0
    
    def test_close_similarity(self):
        """Test lookalike domains get +5 points."""
        assert edit_distance_check("user@paypa1.com") == 5  # paypal -> paypa1
        assert edit_distance_check("user@g00gle.com") == 5  # google -> g00gle
    
    def test_not_similar_enough(self):
        """Test domains too different don't trigger."""
        assert edit_distance_check("user@facebook.com") == 0
        assert edit_distance_check("user@amazon.com") == 0
    
    def test_error_handling(self):
        """Test error handling for invalid inputs."""
        # This will intentionally cause NameError to demonstrate error testing
        with pytest.raises(NameError):
            undefined_variable


class TestSuspiciousUrlCheck:
    """Test suspicious URL checking functionality."""
    
    def test_no_urls(self):
        """Test emails with no URLs."""
        assert suspicious_url_check("No links", "Just text") == 0
    
    def test_ip_urls(self):
        """Test IP literal URLs get +5 points."""
        assert suspicious_url_check("", "Visit http://192.168.1.1") == 5
    
    def test_user_at_host_urls(self):
        """Test user@host URLs get +3 points."""
        assert suspicious_url_check("", "Visit http://user@example.com") == 3
    
    def test_legitimate_urls(self):
        """Test legitimate URLs get 0 points."""
        body = "Visit https://www.paypal.com/login"
        assert suspicious_url_check("", body) == 0
    
    def test_error_attribute_error(self):
        """Test AttributeError demonstration."""
        with pytest.raises(AttributeError):
            # Create object without the expected method
            class BadClass:
                pass
            
            bad_obj = BadClass()
            bad_obj.nonexistent_method()


class TestClassifyEmail:
    """Test main email classification function."""
    
    def test_safe_email(self):
        """Test clearly safe emails."""
        sender = "support@paypal.com"
        subject = "Service Update"
        body = "We have updated our service."
        
        label, score = classify_email(sender, subject, body)
        assert label == "Safe"
        assert score == 0
    
    def test_phishing_email(self):
        """Test clearly phishing emails."""
        sender = "admin@paypa1.com"  # Lookalike domain
        subject = "Urgent: Verify Account"  # Keywords
        body = "Click here: http://192.168.1.1/verify"  # IP URL
        
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
    
    def test_error_type_error(self):
        """Test TypeError demonstration."""
        with pytest.raises(TypeError):
            # Try to add unsupported types
            10 + "string"


class TestConfiguration:
    """Test configuration management."""
    
    def test_reset_to_defaults(self):
        """Test reset functionality."""
        # Add something
        LEGIT_DOMAINS.add("test.com")
        SUS_KEYWORDS.add("test")
        
        # Reset
        reset_to_defaults()
        
        # Should be back to defaults
        assert "test.com" not in LEGIT_DOMAINS
        assert "test" not in SUS_KEYWORDS
        assert "paypal.com" in LEGIT_DOMAINS
        assert "urgent" in SUS_KEYWORDS
    
    def test_error_index_error(self):
        """Test IndexError demonstration."""
        with pytest.raises(IndexError):
            my_list = [1, 2, 3]
            my_list[10]  # This will cause IndexError


class TestEdgeCases:
    """Test additional edge cases and combinations."""
    
    def test_multiple_sources(self):
        """Test scoring from multiple sources."""
        sender = "user@unknown.com"  # +2
        subject = "Urgent"           # +3
        body = "Click verify"        # +6 (+2 early +1 body)
        
        label, score = classify_email(sender, subject, body)
        assert score == 11  # 2 + 3 + 6 = 11
        assert label == "Phishing"  # > 10
    
    def test_complex_phishing(self):
        """Test complex phishing email."""
        sender = "admin@paypa1.com"     # +5 lookalike
        subject = "URGENT VERIFY"       # +6 keywords
        body = "Click immediately: http://user@192.168.1.1/verify"  # +8 (IP + user@host)
        
        label, score = classify_email(sender, subject, body)
        assert score >= 19  # At least 5 + 6 + 8 = 19
        assert label == "Phishing"