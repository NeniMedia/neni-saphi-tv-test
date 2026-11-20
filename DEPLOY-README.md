# Review-only package — not approved for deployment

This directory is an allowlisted fixture-only copy of the approved SAPHI frontend. It has no production backend, credentials, databases, proxy or upstream URL. Do not import the existing Neni Stream repository into a hosting provider. If separately approved, upload ONLY this generated package to a new private repository and create a separate Render service.

The proposed runtime is Python 3.13 with Gunicorn 27.0.1, one worker and four threads, on Render's free web-service plan in Frankfurt. Auto-deploy is off. `render.yaml` sets TEST_ENABLED=false. Applying a Blueprint still creates an internet-facing service even with auto-deploy off; do not apply it before explicit approval.

Required environment settings: TEST_HOST (exact assigned hostname), TEST_PIN_SALT and TEST_PIN_HASH (temporary passcode verifier, never production credentials), TEST_EXPIRES_AT (Unix UTC seconds, proposed 48 hours), TEST_ENABLED (must explicitly become true after the approved access setup).

Render terminates HTTPS at its own load balancer. Gunicorn accepts the forwarded scheme because the managed load balancer is the ingress boundary. The app rejects non-HTTPS scheme and unexpected Host/Origin. This configuration must not be used on an independently internet-exposed Gunicorn port. No access log is enabled. Platform request logging/retention is outside this application's control.

The passcode form has an optional ES5 remote-operated numeric keypad and works without JavaScript via ordinary HTML form submission. Every prototype/API/media route needs a two-hour Secure/HttpOnly/SameSite=Lax gate cookie; health and the access screen's CSS/JS are the only public exceptions. Sample account sign-out clears sample state. Restarting clears all gate and sample sessions. No secrets go into browser code, URL query strings or manifests.

The service refuses prototype/API/media access after its absolute expiry even if a cookie remains valid. Expiry does not delete the cloud service or stop all resource usage. The owner must suspend/delete only the new service afterward; no action on Bazzite is required.

Before approval, review HOSTING-PLAN.md in the isolated remote-test source directory. Free services may sleep, restart, reset fixture progress and lose in-memory sessions. This package does not verify the real Philips TV's TLS, cookie support or codecs. Do not disable TLS validation or add production accounts to work around compatibility failures.
