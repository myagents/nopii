"""
Policy models module.

This module re-exports the core Policy and Rule models for backward compatibility
and to provide a clear interface for policy-related models.
"""

from nopii.core.models import Policy, Rule

__all__ = ["Policy", "Rule"]
