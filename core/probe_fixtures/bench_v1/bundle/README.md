Linux, Python 3.12, Flask, PyJWT 2.x. Runs in AWS EC2 (instance metadata service reachable at 169.254.169.254,
IMDSv1 enabled; the instance role can read the production S3 buckets). The app sits behind an AWS load balancer
that APPENDS the connecting client's IP to any X-Forwarded-For header the client sent; the app itself is only
reachable through the load balancer. Every view in app/views.py is a public HTTPS route. Users who never
requested a password reset have reset_token = NULL. APP_JWT_KEY is a long random secret.
/srv/app (code and data) is a single filesystem owned by the service user the app runs as.
