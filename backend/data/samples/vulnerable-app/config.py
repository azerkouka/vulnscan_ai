"""DELIBERATELY VULNERABLE - sample input for the scanner. Never run or deploy."""

# VULNERABLE: credentials committed in source code (these are fake values).
DATABASE_PASSWORD = "example-hardcoded-password"
API_TOKEN = "example-hardcoded-token-0000"

# VULNERABLE: debug mode exposes an interactive console and stack traces.
DEBUG = True
