DOOM v10 audit
==============

Kept
----
The existing doom-v1 UI stays the product surface: chat, media, workflow, automations, connectors, customization, modules, PBE, team, settings, profile. v9 remains the usage gateway. v10 does not replace those screens.

Broken connection found
-----------------------
doom.js had a syntax error in the invitation email string. That stopped every click. Fixed in the v8.1 package. v10 does not depend on that file loading.

What was still disconnected
---------------------------
Plans lived in the page. Web Shop could not change them. Web and app had no shared session. OpenRouter and Composio were named in the UI path. Files had no owner, quota, or storage key.

v10 fixes that boundary
-----------------------
schema.sql is the shared Web Shop + DOOM database: users, subscriptions, entitlements, workspaces, memberships, rules, chats, files, AI employees, sessions.
app/entitlements.py is the only plan map. Downgrade, cancel, and expiry fall back to free. Data is not deleted.
app/providers hides OpenRouter and Composio. The user only sees DOOM.
GET /session is what web and the future app both call. A role of viewer or operator cannot unlock paid powers by editing the page.
POST /sync-plan copies the Web Shop subscription into entitlements immediately. No reinstall.

Not done in this pass
---------------------
Password login, Razorpay webhook, and object storage still need your keys and Web Shop checkout. The tables and routes are ready for them.
