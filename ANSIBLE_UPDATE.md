# Ansible Playbook Updates for /cm Hardening

This document describes the changes needed in
`home/playbooks/openbeken/02-apply.yml` (and `apply_one.yml`) to support
the two new `/cm` security flags:

- **Flag 55** (`OBK_FLAG_CM_POST_ONLY`): `/cm` rejects GET, requires POST
- **Flag 56** (`OBK_FLAG_CM_REQUIRE_HMAC`): `/cm` requires HMAC-SHA256 signature

---

## New inventory variables

Add to `group_vars/openbeken.yml` (or per-device host_vars):

```yaml
# /cm hardening
obk_cm_post_only: true          # enforce POST-only mode (flag 55)
obk_cm_require_hmac: true       # require HMAC signatures (flag 56)
obk_cm_hmac_secret: "changeme"  # shared secret — store in vault
```

---

## Provisioning: set the secret once

Add a one-time provisioning task **before** enabling the flag:

```yaml
- name: Store /cm HMAC secret
  ansible.builtin.uri:
    url: "http://{{ obk_ip }}/cm"
    method: POST
    body: "cmnd=setCMSecret+{{ obk_cm_hmac_secret | urlencode }}"
    headers:
      Content-Type: application/x-www-form-urlencoded
    url_username: "{{ obk_http_username | default('') }}"
    url_password: "{{ obk_http_password | default('') }}"
    force_basic_auth: "{{ force_basic_auth | default(false) }}"
  when: obk_cm_require_hmac | default(false)
```

---

## Helper: compute HMAC signature

Add this task file as `roles/openbeken/tasks/cm_sig.yml`:

```yaml
# Computes HMAC-SHA256(obk_cm_hmac_secret, _cm_cmd) → _cm_sig
- name: Compute /cm HMAC signature
  ansible.builtin.command:
    argv:
      - python3
      - -c
      - |
        import hmac, hashlib, sys
        key = sys.argv[1].encode()
        msg = sys.argv[2].encode()
        print(hmac.new(key, msg, hashlib.sha256).hexdigest(), end='')
      - "{{ obk_cm_hmac_secret }}"
      - "{{ _cm_cmd }}"
  register: _cm_sig_result
  delegate_to: localhost
  changed_when: false
  when: obk_cm_require_hmac | default(false)

- name: Set _cm_sig fact
  ansible.builtin.set_fact:
    _cm_sig: "{{ _cm_sig_result.stdout if (obk_cm_require_hmac | default(false)) else '' }}"
```

---

## Updated /cm send task

Replace the existing GET-based task with this:

```yaml
- name: Send /cm command
  vars:
    _cm_body_base: "cmnd={{ _cm_cmd | urlencode }}"
    _cm_body: "{{ _cm_body_base + '&sig=' + _cm_sig | urlencode if _cm_sig else _cm_body_base }}"
    _cm_method: "{{ 'POST' if (obk_cm_post_only | default(false)) else 'GET' }}"
    _cm_url_get: "http://{{ obk_ip }}/cm?cmnd={{ _cm_cmd | urlencode }}"
    _cm_url_post: "http://{{ obk_ip }}/cm"
  ansible.builtin.uri:
    url: "{{ _cm_url_post if _cm_method == 'POST' else _cm_url_get }}"
    method: "{{ _cm_method }}"
    body: "{{ _cm_body if _cm_method == 'POST' else omit }}"
    headers:
      Content-Type: "{{ 'application/x-www-form-urlencoded' if _cm_method == 'POST' else omit }}"
    url_username: "{{ obk_http_username | default('') }}"
    url_password: "{{ obk_http_password | default('') }}"
    force_basic_auth: "{{ force_basic_auth | default(false) }}"
```

---

## Full provisioning sequence for a new device

```yaml
# 1. Basic config (no auth yet — device is freshly flashed)
- name: Set device name
  include_tasks: cm_send.yml
  vars:
    _cm_cmd: "ShortName {{ inventory_hostname }}"

# ... (other config tasks) ...

# 2. Store HMAC secret (before enabling the flag)
- name: Store /cm HMAC secret
  ansible.builtin.uri:
    url: "http://{{ obk_ip }}/cm"
    method: POST
    body: "cmnd=setCMSecret+{{ obk_cm_hmac_secret | urlencode }}"
    headers:
      Content-Type: application/x-www-form-urlencoded

# 3. Enable POST-only and HMAC flags
- name: Enable /cm hardening flags
  include_tasks: cm_send.yml
  vars:
    _cm_cmd: "SetFlag 55 1"   # POST-only

- name: Enable HMAC flag
  include_tasks: cm_send.yml
  vars:
    _cm_cmd: "SetFlag 56 1"   # require HMAC

# 4. From this point on, all /cm calls must use POST + HMAC
```

---

## Security notes

- Store `obk_cm_hmac_secret` in Ansible Vault, not in plaintext `group_vars`.
- HMAC signing authenticates the sender but does not prevent replay. Combine
  with the IP allowlist (`addAllowedIP 192.168.50.0/24`) to restrict which
  hosts can reach `/cm` at all.
- Flag 55 (POST-only) alone (no HMAC) already blocks CSRF from browser pages
  and IoT-VLAN devices. Enable it even if you don't want the complexity of HMAC.
- Once flag 56 is enabled, `setCMSecret` itself requires a valid signature —
  so set the secret **before** enabling the flag.
