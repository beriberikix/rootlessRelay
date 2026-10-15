"use strict";

// Operator sign-in through an external OpenID Connect provider (e.g. Auth0)
// for the admin panel: authorization code flow with PKCE, handled server
// side. A login is accepted only when the provider's subject maps to an
// active operator account (users.external_sub = "<iss>|<sub>", the same form
// the relay uses for external JWTs), and, with requireMfa, only when the ID
// token says multi-factor authentication was performed (amr contains "mfa").

const crypto = require("node:crypto");
const jose = require("jose");

const STATE_TTL_MS = 10 * 60 * 1000;

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function createOidcLogin({
  issuer,
  clientId,
  clientSecret,
  redirectUrl,
  users,
  requireMfa = true,
  log = null,
  fetchFn = globalThis.fetch,
  jwks = null,
  now = Date.now,
}) {
  const redirect = new URL(redirectUrl);
  let discovery = null;
  let keySet = jwks;

  async function discover() {
    if (discovery) return discovery;
    const url = new URL(".well-known/openid-configuration", issuer.endsWith("/") ? issuer : `${issuer}/`);
    const res = await fetchFn(url);
    if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
    discovery = await res.json();
    if (!keySet) keySet = jose.createRemoteJWKSet(new URL(discovery.jwks_uri));
    return discovery;
  }

  function fail(res, status, message) {
    res.status(status).type("text/plain").send(`${message}\n\nReturn to the panel: ${redirect.origin}/`);
  }

  function mount(app) {
    app.get("/auth/login", async (req, res, next) => {
      try {
        // Session cookies are per host: start on the host the provider will
        // redirect back to, or the state saved here would be lost.
        if (req.headers.host !== redirect.host) {
          res.redirect(`${redirect.origin}/auth/login`);
          return;
        }
        const meta = await discover();
        const state = b64url(crypto.randomBytes(24));
        const nonce = b64url(crypto.randomBytes(24));
        const verifier = b64url(crypto.randomBytes(32));
        req.session.oidc = { state, nonce, verifier, at: now() };
        const url = new URL(meta.authorization_endpoint);
        url.search = new URLSearchParams({
          response_type: "code",
          client_id: clientId,
          redirect_uri: redirect.href,
          scope: "openid email",
          state,
          nonce,
          code_challenge: b64url(crypto.createHash("sha256").update(verifier).digest()),
          code_challenge_method: "S256",
        }).toString();
        req.session.save((error) => (error ? next(error) : res.redirect(url.href)));
      } catch (error) {
        next(error);
      }
    });

    app.get(redirect.pathname, async (req, res, next) => {
      try {
        const pending = req.session.oidc;
        delete req.session.oidc;
        if (req.query.error) {
          fail(res, 401, `Sign-in was not completed: ${String(req.query.error_description || req.query.error).slice(0, 200)}`);
          return;
        }
        if (!pending || typeof req.query.state !== "string" || req.query.state !== pending.state
          || now() - pending.at > STATE_TTL_MS || typeof req.query.code !== "string") {
          fail(res, 400, "Sign-in expired or was started elsewhere. Start again.");
          return;
        }
        const meta = await discover();
        const tokenRes = await fetchFn(meta.token_endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code: req.query.code,
            redirect_uri: redirect.href,
            client_id: clientId,
            client_secret: clientSecret,
            code_verifier: pending.verifier,
          }),
        });
        const tokens = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || typeof tokens.id_token !== "string") {
          log?.warn("operator OIDC code exchange failed", { status: tokenRes.status, error: tokens.error });
          fail(res, 401, "Sign-in failed at the identity provider.");
          return;
        }
        const { payload } = await jose.jwtVerify(tokens.id_token, keySet, {
          issuer: meta.issuer,
          audience: clientId,
          algorithms: ["RS256"],
          currentDate: new Date(now()),
        });
        if (payload.nonce !== pending.nonce) {
          fail(res, 401, "Sign-in failed (nonce mismatch).");
          return;
        }
        if (requireMfa && !(Array.isArray(payload.amr) && payload.amr.includes("mfa"))) {
          log?.warn("operator OIDC login without MFA refused", { sub: payload.sub });
          fail(res, 403, "This panel requires multi-factor authentication.");
          return;
        }
        const user = await users.findByExternalSub(`${payload.iss}|${payload.sub}`);
        if (!user || user.role !== "operator" || user.status !== "active") {
          log?.warn("operator OIDC login for a non-operator refused", { sub: payload.sub, email: payload.email });
          fail(res, 403, `${payload.email || payload.sub} is not an operator.`);
          return;
        }
        await users.touchLogin(user.id);
        req.logIn({ id: user.id, username: user.username, role: user.role }, (error) => {
          if (error) {
            next(error);
            return;
          }
          log?.info("operator signed in via OIDC", { userId: user.id });
          res.redirect("/");
        });
      } catch (error) {
        log?.warn("operator OIDC callback failed", { error: error && error.message });
        fail(res, 401, "Sign-in failed.");
      }
    });
  }

  return { mount, discover };
}

module.exports = { createOidcLogin };
