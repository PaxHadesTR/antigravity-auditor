Ledger service. Every request handler in app/views.py and app/files.py is reachable by any client over HTTPS.
Users self-register (role 'user'); is_admin() decides admin access from users.role. LEDGER_SECRET,
LEDGER_CACHE_KEY are long random values set in production; the report cache blobs are written only by the server.
