# Security Review — `edupage-api`

**Date:** 2026-05-07
**Reviewer:** Automated security review (Claude Code)
**Branch:** `security-review`
**Scope:** Full repository (`edupage_api/`, `examples/`)
**Result summary:** No high-confidence exploitable vulnerabilities found. A small number of low-severity / informational observations are documented below.

---

## Criticality scale

| Rating | Meaning |
|---|---|
| **Critical** | Directly exploitable by an unauthenticated remote attacker; RCE / auth bypass / mass data breach. |
| **High** | Exploitable with realistic preconditions; significant impact (auth bypass, account compromise, data theft). |
| **Medium** | Exploitable under specific conditions or with limited impact. |
| **Low** | Defense-in-depth issue, hardening gap, or minor information leak. |
| **Informational** | Not a vulnerability; documented for awareness. |

---

## Methodology

This is a thin, client-side Python wrapper around EduPage's HTTP API. It is consumed as a library (`pip install edupage-api`) by trusted application code that supplies a username, password and school subdomain. The library itself does not run a server, does not receive untrusted network input, and does not parse hostile content.

The following were examined:

- HTTP request construction in every module (URLs, headers, cookies, body)
- Authentication and 2FA flow (`edupage_api/login.py`)
- TLS / certificate handling (`requests` defaults — no `verify=False`)
- Deserialization (`json`, `pickle`, `yaml`, `eval`, `exec`)
- Subprocess / OS / shell execution
- File system operations and path handling
- Cryptographic primitives (`hashlib`, `secrets`, `random`)
- Hardcoded credentials or tokens
- HTML/JSON parsing of EduPage server responses

Searches performed across the codebase:

```
grep -rn "pickle\|yaml.load\|eval(\|exec(\|subprocess\|os.system\|shell=True\|verify=False" edupage_api/
# → no matches
```

No matches were found for any dangerous primitive.

---

## Findings

### Finding 1 — SHA-1 used as a protocol checksum

* **Criticality:** Informational
* **File:** `edupage_api/compression.py:178`
* **Category:** Crypto (non-security usage)

**Code:**

```python
171    @staticmethod
172    def encode_request_body(request_data: Union[dict, str]) -> str:
173        encoded_data = (
174            ModuleHelper.encode_form_data(request_data)
175            if type(request_data) == dict
176            else request_data
177        )
178        encoded_data = RequestData.__encode_data(encoded_data)
179        data_hash = sha1(encoded_data.encode()).hexdigest()
180
181        return ModuleHelper.encode_form_data(
182            {
183                "eqap": f"dz:{encoded_data}",
184                "eqacs": data_hash,
185                "eqaz": "1",  # use "encryption"? (compression)
186            }
187        )
```

**Assessment:** SHA-1 is computed over the already-base64-encoded request body and sent as the `eqacs` integrity field, which is the wire format expected by the EduPage server. This is a non-security checksum (collision resistance is not a property the protocol relies on for authentication or signing). Replacing it would break interoperability with the EduPage backend. **No action required.**

---

### Finding 2 — String-based parsing of server-returned HTML/JS

* **Criticality:** Low (informational; not exploitable in this trust model)
* **File:** `edupage_api/login.py:123-135`, `:169`, `:208-211`
* **Category:** Robustness / parser fragility

**Code:**

```python
122    class Login(Module):
123        def __parse_login_data(self, data):
124            json_string = (
125                data.split("userhome(", 1)[1]
126                .rsplit(");", 2)[0]
127                .replace("\t", "")
128                .replace("\n", "")
129                .replace("\r", "")
130            )
131
132            self.edupage.data = json.loads(json_string)
133            self.edupage.is_logged_in = True
134
135            self.edupage.gsec_hash = data.split('ASC.gsechash="')[1].split('"')[0]
```

```python
169            csrf_token = data.split('"csrftoken":"')[1].split('"')[0]
```

```python
208            csrf_token = data.split('csrfauth" value="')[1].split('"')[0]
209
210            authentication_token = data.split('au" value="')[1].split('"')[0]
211            authentication_endpoint = data.split('gu" value="')[1].split('"')[0]
```

**Assessment:** The library extracts JSON / CSRF tokens out of the HTML returned by `*.edupage.org` using `str.split`. Because the response is delivered over HTTPS from a server the user has already chosen to trust with their credentials, this is not a security boundary. It is, however, fragile: a server-side template change can raise `IndexError` or feed malformed input into `json.loads`. **No security action; consider hardening if the upstream HTML changes break the parser in production.**

---

### Finding 3 — `CustomRequest.custom_request` silently returns `None` on unknown method

* **Criticality:** Low (correctness, not security)
* **File:** `edupage_api/custom_request.py:7-15`
* **Category:** Input handling

**Code:**

```python
 6    class CustomRequest(Module):
 7        def custom_request(
 8            self, url: str, method: str, data: str = "", headers: dict = {}
 9        ) -> Response:
10            if method == "GET":
11                response = self.edupage.session.get(url, headers=headers)
12            elif method == "POST":
13                response = self.edupage.session.post(url, data=data, headers=headers)
14
15            return response
```

**Assessment:** If `method` is anything other than `"GET"` or `"POST"`, `response` is unbound and the function raises `UnboundLocalError`. This is a robustness defect, not a security issue — `url`, `method`, `data`, `headers` are all supplied by the trusted library consumer. The `requests.Session` cookies (including `PHPSESSID`) are sent to whatever URL the consumer specifies, but the consumer is the legitimate owner of those cookies. **No security action.**

---

## Categories explicitly checked — none found

| Category | Result |
|---|---|
| SQL injection | Not applicable (no DB layer) |
| Command injection / shell execution | No `subprocess`, `os.system`, or `shell=True` anywhere |
| Insecure deserialization | Only `json.loads` on EduPage HTTPS responses; no `pickle`, no `yaml.load`, no `eval`/`exec` |
| Path traversal / unsafe file ops | No file reads/writes on user-controlled paths |
| TLS / certificate validation bypass | No `verify=False`; default `requests` validation in use |
| Hardcoded credentials or API keys | None |
| Weak randomness in security-critical paths | No use of `random` for tokens; tokens are obtained from the server |
| XSS / template injection | Library does not render HTML or run a templating engine |
| SSRF (host/protocol controllable by attacker) | URLs are built from a `subdomain` argument supplied by the library consumer; not attacker-controlled |
| 2FA bypass logic | Flow in `login.py:59-119` correctly requires either device confirmation (`is_confirmed` → server-issued `code`) or a user-supplied code before calling `__finish` |

---

## Trust model note

This library runs **inside the user's own application**, with credentials the user already owns. The relevant attacker model is therefore "malicious EduPage server" or "MITM on the wire". TLS via `requests` mitigates the latter; the former is out of scope (the user has voluntarily supplied their password to that server). There is no scenario in which a third-party attacker supplies input to this library across a trust boundary.

## Conclusion

**No high- or medium-confidence security vulnerabilities were identified.** The three findings above are informational/low and do not warrant code changes for security reasons.
