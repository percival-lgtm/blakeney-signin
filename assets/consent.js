// Blakeney sign-in + OAuth consent page (static; holds no secrets).
// Supabase Auth sends you here with ?authorization_id=... when an app (e.g. a Grok bot) asks to connect.
// You sign in, optionally pass your authenticator check, see exactly which app is asking, and Approve or Deny.
(function () {
  "use strict";

  // Refuse to run inside a frame (stops another site from overlaying this page to trick a click).
  if (window.top !== window.self) {
    document.body.textContent = "This page can't be shown inside another site.";
    return;
  }

  const meta = (n) => (document.querySelector(`meta[name="${n}"]`) || {}).content || "";
  const SUPABASE_URL = meta("blakeney-supabase-url");
  const PUBLISHABLE_KEY = meta("blakeney-publishable-key");
  const LABEL = meta("blakeney-label");
  const REQUIRE_MFA = meta("blakeney-require-mfa") === "true";

  const $ = (id) => document.getElementById(id);
  const show = (id) => { for (const s of document.querySelectorAll("section")) s.hidden = s.id !== id; };
  const say = (msg, isError) => { const m = $("msg"); m.textContent = msg || ""; m.className = isError ? "msg err" : "msg"; };

  $("label").textContent = LABEL;

  const sb = window.supabase.createClient(SUPABASE_URL, PUBLISHABLE_KEY, {
    auth: {
      storage: window.sessionStorage,   // signed out when you close the tab
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
    },
  });

  const params = new URLSearchParams(window.location.search);
  const rawId = params.get("authorization_id") || "";
  const authorizationId = /^[A-Za-z0-9_-]{8,128}$/.test(rawId) ? rawId : "";

  async function aal() {
    const { data } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
    return data || { currentLevel: null, nextLevel: null };
  }

  async function verifiedTotp() {
    const { data } = await sb.auth.mfa.listFactors();
    return ((data && data.totp) || []).find((f) => f.status === "verified") || null;
  }

  async function route() {
    say("");
    const { data: { session } } = await sb.auth.getSession();
    if (!session) return show("login");

    $("who").textContent = session.user.email || "(no email)";
    const level = await aal();
    if (level.nextLevel === "aal2" && level.currentLevel !== "aal2") return show("mfa");

    if (!authorizationId) {
      $("mfa-status").textContent = level.currentLevel === "aal2"
        ? "Authenticator: on and checked for this sign-in."
        : "Authenticator: not set up yet.";
      $("enroll-start").hidden = level.currentLevel === "aal2";
      return show("home");
    }

    if (REQUIRE_MFA && level.currentLevel !== "aal2") {
      say("Set up your authenticator first (open this page without a request), then try connecting again.", true);
      return show("home");
    }

    const { data, error } = await sb.auth.oauth.getAuthorizationDetails(authorizationId);
    if (error || !data) {
      say("This request is invalid or has expired. Start the connection again from the app.", true);
      return show("home");
    }
    if (!("authorization_id" in data) && data.redirect_url) {
      // Already approved earlier for this app; Supabase hands back where to continue.
      window.location.assign(data.redirect_url);
      return;
    }

    const client = data.client || {};
    let host = "";
    try { host = new URL(data.redirect_uri).host; } catch (_) { host = "(unreadable address)"; }
    $("client-name").textContent = client.name || client.client_name || "(no name given)";
    $("client-id").textContent = client.id || client.client_id || "";
    $("redirect-host").textContent = host;
    $("redirect-uri").textContent = data.redirect_uri || "";
    $("scopes").textContent = (data.scope || "").trim() || "(none listed)";
    show("consent");
  }

  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    say("Signing in…");
    const { error } = await sb.auth.signInWithPassword({
      email: $("email").value.trim(),
      password: $("password").value,
    });
    $("password").value = "";
    if (error) return say("Sign-in failed. Check your email and password.", true);
    route();
  });

  $("mfa-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const factor = await verifiedTotp();
    if (!factor) return say("No authenticator found on this account.", true);
    const { error } = await sb.auth.mfa.challengeAndVerify({ factorId: factor.id, code: $("mfa-code").value.trim() });
    $("mfa-code").value = "";
    if (error) return say("That code didn't work. Try the newest code.", true);
    route();
  });

  let enrollingFactorId = null;
  $("enroll-start").addEventListener("click", async () => {
    // Clear any half-finished setups so they don't pile up.
    const { data: list } = await sb.auth.mfa.listFactors();
    for (const f of ((list && list.all) || [])) {
      if (f.status === "unverified") await sb.auth.mfa.unenroll({ factorId: f.id });
    }
    const { data, error } = await sb.auth.mfa.enroll({ factorType: "totp", friendlyName: "Blakeney authenticator" });
    if (error || !data) return say("Couldn't start authenticator setup.", true);
    enrollingFactorId = data.id;
    $("qr").src = data.totp.qr_code;           // a data: image made by Supabase
    $("totp-secret").textContent = data.totp.secret;
    show("enroll");
  });

  $("show-secret").addEventListener("click", () => { $("totp-secret").hidden = !$("totp-secret").hidden; });

  $("enroll-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!enrollingFactorId) return;
    const { error } = await sb.auth.mfa.challengeAndVerify({ factorId: enrollingFactorId, code: $("enroll-code").value.trim() });
    $("enroll-code").value = "";
    if (error) return say("That code didn't work. Try the newest code.", true);
    $("qr").removeAttribute("src");
    $("totp-secret").textContent = "";
    enrollingFactorId = null;
    say("Authenticator is on.");
    route();
  });

  $("approve").addEventListener("click", async () => {
    $("approve").disabled = $("deny").disabled = true;
    say("Approving…");
    const { error } = await sb.auth.oauth.approveAuthorization(authorizationId); // redirects back to the app
    if (error) { say("Approval failed: " + error.message, true); $("approve").disabled = $("deny").disabled = false; }
  });

  $("deny").addEventListener("click", async () => {
    $("approve").disabled = $("deny").disabled = true;
    const { error } = await sb.auth.oauth.denyAuthorization(authorizationId); // redirects back to the app
    if (error) { say("Couldn't send the denial: " + error.message, true); $("approve").disabled = $("deny").disabled = false; }
  });

  for (const b of document.querySelectorAll(".signout")) {
    b.addEventListener("click", async () => { await sb.auth.signOut(); route(); });
  }

  route();
})();
