# azpim

[![CI](https://github.com/winebarrel/azpim/actions/workflows/ci.yml/badge.svg)](https://github.com/winebarrel/azpim/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/winebarrel/azpim/branch/main/graph/badge.svg)](https://codecov.io/gh/winebarrel/azpim)
[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)

Activate and deactivate your own Azure PIM assignments from the command line.

Covers Microsoft Entra ID directory roles and PIM for Groups. Both are
"selfActivate" operations, so azpim only ever acts as the signed-in user on
that user's own eligible assignments — there is no app-only mode.

## Installation

Download an archive for your platform from the
[releases page](https://github.com/winebarrel/azpim/releases) and put the
`azpim` binary somewhere on your `PATH`:

```
tar xzf azpim_Darwin_arm64.tar.gz
install azpim /usr/local/bin/
```

`checksums.txt` in each release covers the archives, if you want to verify one.

Or build it yourself with Go 1.27 or later:

```
go install github.com/winebarrel/azpim/cmd/azpim@latest
```

Either way, `azpim --version` reports what you have.

## Usage

```
Usage: azpim <command> [flags]

Commands:
  role list                       List the directory roles you are eligible for.
  role active                     List the directory roles currently assigned to you.
  role requests                   List your recent activation requests and their approval status.
  role activate <role>            Activate a directory role you are eligible for.
  role deactivate <role>          Deactivate a directory role you have active.

  group list                      List the group memberships you are eligible for.
  group active                    List the group memberships currently assigned to you.
  group requests                  List your recent activation requests and their approval status.
  group activate <group>          Activate a group membership you are eligible for.
  group deactivate <group>        Deactivate a group membership you have active.

Flags:
      --tenant-id=STRING   Tenant to sign in to ($AZPIM_TENANT_ID).
      --client-id=STRING   Application to sign in through ($AZPIM_CLIENT_ID).
      --scope=SCOPE,...    Delegated scopes to request instead of the ones the
                           command would ask for ($AZPIM_SCOPE).
```

```
$ azpim role list
ROLE                    SCOPE   MEMBER TYPE  EXPIRES
Global Reader           tenant  Direct       permanent
Helpdesk Administrator  tenant  Direct       permanent
User Administrator      tenant  Direct       permanent

$ azpim role activate "global reader" --duration 2h --justification "INC-1234"
requested Global Reader for PT2H (Provisioned)

$ azpim role deactivate "global reader"
deactivated Global Reader (Revoked)
```

Roles and groups are named by their display name in full, case-insensitively.
The match is exact, because one role's name can be contained in another's, and
a name matching more than one assignment is an error listing the candidates
rather than a guess, since activating the wrong role is not a harmless mistake.

`--duration` takes a Go duration (`8h`, `1h30m`) or ISO 8601 (`PT8H`, `P1D`).
It defaults to 8 hours and must stay within the role's PIM policy.

Being eligible for a group as both member and owner is normal, so
`group activate` accepts `--access member|owner` to say which one is meant.

Listings go to stdout and can be piped; everything else goes to stderr.

## Authentication

azpim signs in with the authorization code flow and PKCE, redirecting to a
loopback address. It opens your browser, and the token is cached under
`~/.cache/azpim` (mode 0600) and renewed with its refresh token, so signing in
is a once-in-a-while thing.

The device code flow is deliberately not used: tenants commonly block it with a
Conditional Access authentication-flow policy, which no client-side change can
work around. The browser flow also runs in your normal browser session, so
device-compliance conditions are satisfied the same way they are for the portal.

### Multi-factor authentication on activation

A role can sit behind a Conditional Access authentication context, which
requires you to authenticate again — usually with MFA — at the moment you
activate rather than when you signed in. PIM refuses such an activation with
`RoleAssignmentRequestAcrsValidationFailed` and a claims challenge naming the
context it wants.

azpim answers that challenge: it signs you in again carrying the claims, then
sends the same request once more. Expect a browser to open mid-command the
first time, and not again until that token expires — a token issued for a
challenge is cached apart from the ordinary one. The claims are never sent
unprompted, because which contexts exist and which roles require them is a
per-tenant setting.

### Which application it signs in through

`--client-id` defaults to Microsoft Graph PowerShell
(`14d82eec-204b-4c2f-b7e8-296a70dab67e`), the first-party public client that
`Connect-MgGraph` uses. PowerShell itself is not needed or invoked.

The Azure CLI application cannot be used. The delegated Graph scopes Microsoft
grants it are fixed and contain nothing from PIM, so a token borrowed from
`az account get-access-token` is rejected by every endpoint azpim calls, no
matter how you sign in.

Sign-ins are recorded against whichever application is used, and only scopes the
tenant has already consented to can ever be issued. If your organization would
rather you not sign in through Graph PowerShell, register a public client of
your own with the scopes below and pass `--client-id`.

### Scopes

Each command asks for only the scopes its own area needs, so a tenant that has
consented to one area keeps working there even if the other is unavailable.
Tokens are cached per scope set for the same reason.

Directory roles:

- `RoleEligibilitySchedule.Read.Directory`
- `RoleManagement.ReadWrite.Directory`

Groups:

- `PrivilegedEligibilitySchedule.Read.AzureADGroup`
- `PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup`
- `Directory.Read.All` (only to turn group ids into names)

All of these require admin consent. Note that `PrivilegedAccess.*.AzureAD` and
`PrivilegedAccess.*.AzureADGroup` are different scopes despite the names: consent
to the former grants nothing over groups.

If a command fails with `PermissionScopeNotGranted`, the error names the scopes
the tenant is missing. Use `--scope` to request a different set — for example
when the tenant has consented to `RoleAssignmentSchedule.ReadWrite.Directory`
instead of `RoleManagement.ReadWrite.Directory`.

## Approvals

A role whose policy requires approval answers with `PendingApproval` rather than
refusing. azpim says so explicitly, because an accepted request is not the same
as access. Follow it with `azpim role requests`.
