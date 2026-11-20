Payments relay for small merchants. Linux, CPython 3.12, stdlib only. server.py (not shown) serves /signup and /login
itself; login sets a session cookie built from the user's current row in the users table. For every other
request server.py sets request.user to the User from auth.load_session (or None) and calls routes.dispatch; no
other paths than /signup, /login and those in routes.ROUTES are reachable. db.save_user stores every field of
the User object. Anyone can sign up, so "logged-in user" means any member of the public with a free account.
users.role is "member" or "admin"; admins can export every user's data. RELAY_SECRET is a long random value.
Balances are integers in cents and belong to their users. Password reset: the user (or anyone who knows the
user's email) calls start_reset; the token is emailed to the user and finish_reset sets a new password for
whoever presents the right token. The HTTP Date header of every response shows the server time to the second.
