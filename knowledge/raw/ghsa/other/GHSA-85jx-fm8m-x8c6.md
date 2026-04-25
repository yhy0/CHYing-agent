# zot’s create-only policy allows overwrite attempts of existing latest tag (update permission not required)

**GHSA**: GHSA-85jx-fm8m-x8c6 | **CVE**: CVE-2026-31801 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-863

**Affected Packages**:
- **zotregistry.dev/zot/v2** (go): < 2.1.15
- **zotregistry.dev/zot** (go): >= 1.3.0-20210831063041-c8779d9e87d9, <= 1.4.4-20251014054906-73eef25681af

## Description

zot’s dist-spec authorization middleware infers the required action for `PUT /v2/{name}/manifests/{reference}` as `create` by default, and only switches to `update` when the tag already exists and `reference != "latest"`.

as a result, when `latest` already exists, a user who is allowed to `create` (but not allowed to `update`) can still pass the authorization check for an overwrite attempt of `latest`.

## affected component

- file: `pkg/api/authz.go` (`DistSpecAuthzHandler`)
- condition: `slices.Contains(tags, reference) && reference != "latest"` (line 352 at the pinned commit)

## severity

HIGH
category: CWE-863 (incorrect authorization)

note: impact depends on how a deployment uses `latest` (for example, if `latest` is treated as a protected or “push-once” tag), and on how access control is provisioned (users with `create` but without `update`). the attached poc demonstrates a real overwrite of `latest` (tag digest changes) under a create-only policy.

## steps to reproduce

1. configure access control so user `attacker` has `create` but not `update` on a repository.
2. ensure the repository has an existing tag named `latest`.
3. attempt to push a new manifest to `/v2/acme/app/manifests/latest` (example repository name).
4. observe that the authorization check is evaluated as `create` (not `update`) for `latest`, so the request passes authorization even though the tag already exists.

the attached poc demonstrates this deterministically with `canonical.log` and `control.log` markers.

## expected vs actual

- expected: overwriting an existing tag should require `update` permission, including `latest` (or `latest` should be explicitly documented as exempt).
- actual: when `reference=="latest"` and the tag exists, the middleware keeps the action as `create` instead of switching to `update`.

## security impact

this can break least-privilege expectations in deployments that rely on the `create` vs `update` split to prevent tag overwrites (for example, “push-once” policies). if `latest` is used as a high-trust tag in ci/cd, this can create supply-chain risk because a create-only principal can overwrite an existing `latest` tag while other existing tags correctly require `update`.

## suggested fix

remove the special-case exemption for `latest` when determining whether an existing tag requires `update` permission (treat `latest` the same as other tags), or document and enforce an explicit policy rule for `latest`.

## notes / rationale

- oci distribution spec does not define a standard authorization model; this report is about zot’s own create vs update semantics and the observable behavior in `DistSpecAuthzHandler`.
- zot documentation describes immutable tags as being enforceable via authorization policies (create-only “push once”, update disallowed). if `latest` is exempt, this control does not apply to `latest` unless documented otherwise.

[addendum.md](https://github.com/user-attachments/files/24986139/addendum.md)
[poc.zip](https://github.com/user-attachments/files/24986140/poc.zip)
[PR_DESCRIPTION.md](https://github.com/user-attachments/files/24986141/PR_DESCRIPTION.md)
[RUNNABLE_POC.md](https://github.com/user-attachments/files/24986142/RUNNABLE_POC.md)
