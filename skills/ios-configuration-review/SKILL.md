---
name: ios-configuration-review
description: >-
  Pre-execution and post-execution Cisco IOS auditing using AgenticNet capability
  profiles, static validators, mode safety, configuration backups/diffs, and
  secret redaction.
---

# IOS Configuration Review

Audit every CLI sequence against the target Packet Tracer device model before pushing it live, and verify changes with redacted config snapshots.

## 1. Pre-Execution Audit Checklist

Before calling `console_execute`:
1. **Verify Target Model Support (`device_capabilities`):**
   - Confirm the target supports `ios_cli` (`PC-PT`, `Laptop-PT`, `Server-PT`, `Printer-PT`, `WRT300N`, `AccessPoint-PT`, `7960`, `Home-VOIP-PT` do **not**—use `host_configure` or GUI).
   - Check interface naming conventions (`Gi0/0` on `2911`/`1941`, `Fa0/0` on `2811`, `Gi0/0/0` on `4321`, `Gi1/0/1` on `3650-24PS`, `Se2/0` on `Router-PT`).
2. **Validate Platform-Specific IOS Rules (`command_validate` in `advanced`, or manual check matching `validators.py`):**
   - **No `ip routing`, `router ospf/eigrp/rip/bgp`, `ip nat`, or `encapsulation dot1q`** on Layer 2 switches (`2960-24TT`, `Switch-PT`).
   - **No `switchport`** commands on routers (`2911`, `1941`, `2811`, `4321`, `Router-PT`).
   - **Trunk encapsulation rule:** Never send `switchport trunk encapsulation dot1q` to `2960-24TT`; always send `switchport trunk encapsulation dot1q` **before** `switchport mode trunk` on `3560-24PS` and `3650-24PS`.
   - **L3 switch routed port:** Send `no switchport` before `ip address` on `3560-24PS` / `3650-24PS` physical ports.
   - **Valid IP/Mask:** Confirm contiguous subnet masks and non-overlapping interface subnets (`subnet_calculate`).
3. **CLI Mode & Prompt Safety:**
   - Do not mix exec `show` commands bare inside `(config)#`; prefix with `do show ...` or exit back to `#` (`end`), or use `verification_commands` on `console_execute`.
   - Never send a bare `"no"` command to Catalyst switches (`2960-24TT`, `3560-24PS`, `3650-24PS`)—switches have no setup dialog and a bare `no` triggers slow DNS lookup unless `no ip domain-lookup` is active.
   - Include `no ip domain-lookup` on routers/switches to prevent typo hangs.
   - Explicitly add `no shutdown` on every configured router/SVI/switch interface.

## 2. Execution & Diff Hygiene

- Always capture a pre-change config snapshot via `configuration_backup(device_name=..., fetch_live=True)` when modifying an existing device.
- Use `console_execute(..., dry_run=True)` to preview mode preparation when uncertain, and keep `stop_on_error=True` for critical configs so syntax failures (`% Invalid input`, `% Incomplete command`, `% overlaps with`, `% Bad mask`) halt immediately.
- After execution, take a post-change snapshot (`configuration_backup`), compare (`configuration_compare` in `advanced` or `lab_diff`), and persist running config with `copy running-config startup-config` (or `write memory`) before `lab_save` when NVRAM persistence is graded.

## 3. Secret Redaction

- Never echo plaintext passwords, enable secrets, or bridge tokens in engineering reports; AgenticNet automatically scrubs secrets in `configuration_backup` and SQLite audit logs (`redact_cli_text`).
