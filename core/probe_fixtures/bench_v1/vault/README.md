Document vault for one company. Linux, CPython 3.12, stdlib only. Started as `python -O server.py` (optimisations
on). server.py (not shown) sets request.user to the User whose session cookie auth.session_user accepts, or None,
and then calls the handler in views.py. Every function in views.py is a public HTTPS route. Any employee can
create an account, so "logged-in user" means any employee. Admins are IT operators who already have shell access.
Runs on a cloud VM: the instance metadata service at 169.254.169.254 hands out the VM's cloud credentials to any
plain HTTP GET (no special header or session token needed). VAULT_SECRET_KEY is a long random value; whoever knows it can create a valid session cookie for any
user. User ids are 1, 2, 3, ... Each user's documents are in /srv/vault/docs/<user_id>/ and their archived
documents in /srv/vault/docs-archive/<user_id>/. The CDN host examplecdn.com belongs to the company; anyone can
register other domain names (DNS names may resolve to any address).
