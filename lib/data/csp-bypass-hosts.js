// Script hosts known to host CSP-bypass gadgets (JSONP / AngularJS / user-uploadable content). Seed list from docs/research-csp.md A.
// pattern: lowercase "host" or "host/gadget-path" ("*.domain" allowed as host). Eval-gated hosts (googletagmanager, google-analytics) are omitted on purpose.
const E = 'https://github.com/google/csp-evaluator/tree/master/allowlist_bypasses';
const C = 'https://github.com/renniepak/CSPBypass';
const H = 'https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/content-security-policy-csp-bypass/README.md';

export const BYPASS_HOSTS = [
  { pattern: 'cdnjs.cloudflare.com', reason: 'hosts AngularJS 1.x and prototype-pollution libraries', ref: E },
  { pattern: 'cdn.jsdelivr.net', reason: 'serves any npm/GitHub file incl. AngularJS', ref: E },
  { pattern: 'unpkg.com', reason: 'serves any npm package incl. AngularJS', ref: C },
  { pattern: 'ajax.googleapis.com', reason: 'hosts AngularJS 1.x and JSONP endpoints', ref: E },
  { pattern: 'code.angularjs.org', reason: 'official AngularJS 1.x host', ref: C },
  { pattern: 'cdn.shopify.com', reason: 'serves AngularJS builds and user-supplied assets', ref: E },
  { pattern: 'www.gstatic.com/fsn/angular_js-bundle1.js', reason: 'AngularJS bundle (sandbox-escape gadget)', ref: E },
  { pattern: 'www.google.com/tools/feedback/escalation-options', reason: 'JSONP callback endpoint', ref: E },
  { pattern: 'www.google.com/recaptcha/about/js/main.min.js', reason: 'AngularJS gadget under /recaptcha/', ref: H },
  { pattern: 'accounts.google.com/o/oauth2/revoke', reason: 'JSONP callback endpoint', ref: E },
  { pattern: 'apis.google.com', reason: 'JSONP endpoints', ref: C },
  { pattern: '*.googleapis.com', reason: 'JSONP endpoints (translate., maps., mts*.)', ref: E },
  { pattern: '*.blogspot.com', reason: 'Blogger JSONP feeds', ref: E },
  { pattern: 'www.blogger.com', reason: 'Blogger JSONP feeds', ref: E },
  { pattern: 'api.github.com', reason: 'JSONP endpoints', ref: C },
  { pattern: '*.github.io', reason: 'anyone can publish scripts (AngularJS copies exist)', ref: E },
  { pattern: '*.cloudfront.net', reason: 'JSONP and attacker-hostable scripts', ref: E },
  { pattern: '*.amazonaws.com', reason: 'attacker-hostable scripts (S3)', ref: E },
  { pattern: '*.appspot.com', reason: 'attacker-hostable scripts', ref: E },
  { pattern: '*.herokuapp.com', reason: 'attacker-hostable scripts', ref: E },
  { pattern: '*.azurewebsites.net', reason: 'attacker-hostable scripts', ref: H },
  { pattern: '*.azurestaticapps.net', reason: 'attacker-hostable scripts', ref: H },
  { pattern: '*.firebaseapp.com', reason: 'attacker-hostable scripts', ref: H },
  { pattern: '*.blob.core.windows.net', reason: 'attacker-hostable AngularJS', ref: E },
];
