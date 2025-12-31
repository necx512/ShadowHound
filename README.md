![Logo](./logo.png)

# ShadowHound

ShadowHound is a set of PowerShell scripts for Active Directory enumeration without the need for introducing known-malicious binaries like SharpHound. It leverages native PowerShell capabilities to minimize detection risks and offers two methods for data collection:

- **ShadowHound-ADM.ps1**: Uses the Active Directory module (ADWS).
- **ShadowHound-DS.ps1**: Utilizes direct LDAP queries via `DirectorySearcher`.

## Blog Post

For more details and context, check out the [blog post](https://blog.fndsec.net/2024/11/25/shadowhound/).

Huge thanks to [Itay Yashar](https://www.linkedin.com/in/itay-yashar-55586a163/) for the assistance with the research & development.

## Scripts Overview

### ShadowHound-ADM.ps1

- **Method**: Active Directory module (`Get-ADObject` via ADWS).
- **Usage Scenario**: When the AD module is available and ADWS is accessible.
- **Features**:
  - Handles large domains with `-SplitSearch`, `-Recurse`, and `-LetterSplitSearch` options.
  - Enumerates certificates with the `-Certificates` flag.
  - **Resumable enumeration** - Automatic checkpointing that survives interruptions.
  - **3-letter splitting** - Handles dense prefixes that timeout at 2-letter level.

### ShadowHound-DS.ps1

- **Method**: Direct LDAP queries using `DirectorySearcher`.
- **Usage Scenario**: Environments where the AD module isn't available or LDAP is preferred.
- **Features**:
  - Enumerates certificates with the `-Certificates` flag.
  - Supports alternate credentials with the `-Credential` parameter.

## Usage Examples

### Basic Enumeration

#### ShadowHound-ADM.ps1

```powershell
# Basic usage
ShadowHound-ADM -OutputFilePath "C:\Results\ldap_output.txt"

# Specify a domain controller and custom LDAP filter
ShadowHound-ADM -Server "dc.domain.local" -OutputFilePath "C:\Results\ldap_output.txt" -LdapFilter "(objectClass=user)"

# Use alternate credentials
$cred = Get-Credential
ShadowHound-ADM -OutputFilePath "C:\Results\ldap_output.txt" -Credential $cred -SearchBase "DC=domain,DC=local"
```

#### ShadowHound-DS.ps1

```powershell
# Basic usage
ShadowHound-DS -OutputFile "C:\Results\ldap_output.txt"

# Specify a domain controller
ShadowHound-DS -Server "dc.domain.local" -OutputFile "C:\Results\ldap_output.txt"

# Use a custom LDAP filter
ShadowHound-DS -OutputFile "C:\Results\ldap_output.txt" -LdapFilter "(objectClass=computer)"
```

### Enumerating Certificates

Both scripts support enumerating certificate-related objects for those juicy ADCS vectors:

```powershell
# Using ShadowHound-ADM.ps1
ShadowHound-ADM -OutputFilePath "C:\Results\cert_output.txt" -Certificates

# Using ShadowHound-DS.ps1
ShadowHound-DS -OutputFile "C:\Results\cert_output.txt" -Certificates
```

### Handling Large Domains (ShadowHound-ADM.ps1)

```powershell
# Split search across top-level containers with letter splitting
ShadowHound-ADM -OutputFilePath "C:\Results\ldap_output.txt" -SplitSearch -LetterSplitSearch
```

- **`-SplitSearch`**: Splits the search across top-level containers.
- **`-Recurse`**: Recurses into containers that fail to return results.
- **`-LetterSplitSearch`**: Further splits searches by the first letter of CN.

### Resumable Enumeration (ShadowHound-ADM.ps1)

Enumeration automatically saves progress. If interrupted (network drop, Ctrl+C, session killed), just run the same command again - it picks up where it left off.

```powershell
# Start enumeration
ShadowHound-ADM -Server dc.corp.local -OutputFilePath output.txt -LetterSplitSearch

# Gets interrupted...

# Resume automatically
ShadowHound-ADM -Server dc.corp.local -OutputFilePath output.txt -LetterSplitSearch
```

**New parameters:**
- **`-DisableStateFile`**: No checkpoints (OPSEC - no artifacts)
- **`-StartFromLetter <char>`**: Skip ahead (e.g. `-StartFromLetter "m"`)
- **`-KeepStateFile`**: Preserve state file after completion
- **`-StateFile <path>`**: Custom state file location

For more details on resumable enumeration and 3-letter splitting, see the [feature PR](https://github.com/Friends-Security/ShadowHound/pull/XX).

## Converting Data for BloodHound

If the ldap_output.txt you got using ShadowHound is too large for Bofhound (Memory error), you may split the ShadowHound output using split_output.py:
```bash
# Split ldap_output.txt to 100 chunks which are named split_output_1.txt, split_output_2.txt and so on...
# In order to provide bofhound with a folder containing ldap output, the files *must* be with .log extension.
python3 split_output.py -i ldap_output.txt -o pyldapsearch_ldap -n 100

# Provide Shadowhound with a folder containing the splitted output
python3 bofhound.py -i ./folder -p All --parser ldapsearch
```

After collecting data, use [BofHound](https://github.com/coffeegist/bofhound) to convert it into BloodHound-compatible JSON files:

```bash
python3 bofhound.py -i ldap_output.log -p All --parser ldapsearch
```

For large JSON files (>100MB), consider splitting them with tools like [ShredHound](https://github.com/ustayready/ShredHound).

## Author

- **Yehuda Smirnov**
  - Twitter: [@yudasm_](https://twitter.com/yudasm_)
  - BlueSky: [@yudasm.bsky.social](https://bsky.app/profile/yudasm.bsky.social)
