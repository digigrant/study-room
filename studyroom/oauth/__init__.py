"""Trusted-host provider authorization (SPEC 15.4, 15.5).

These flows run only on the host. Their results (access token, refresh
token, expiry, issued client and account metadata) are stored as one
structured value in the host-specific Infisical path and never enter the
sandbox, which sees only proxy placeholders.
"""
