"""Authoritative DOOM API entrypoint.

All production routes live in server.py so web and desktop clients cannot
drift into separate authentication, entitlement, or tool-execution paths.
"""
from server import app

__all__ = ["app"]
