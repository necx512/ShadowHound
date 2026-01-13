function ShadowHound-ADM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'The domain controller to query.')]
        [string]$Server,

        [Parameter(Mandatory = $false, HelpMessage = 'Path to the output file where results will be saved.')]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFilePath,

        [Parameter(Mandatory = $false, HelpMessage = 'LDAP filter to customize the search.')]
        [string]$LdapFilter = '(ObjectGuid=*)',

        [Parameter(Mandatory = $false, HelpMessage = 'The base DN for the search.')]
        [string]$SearchBase,

        [Parameter(Mandatory = $false, HelpMessage = 'The number of objects to include in one page for paging LDAP searches.')]
        [int]$PageSize = 500,

        [Parameter(Mandatory = $false, HelpMessage = 'PSCredential object for alternate credentials.')]
        [pscredential]$Credential,

        [Parameter(Mandatory = $false, HelpMessage = 'Splits the search across top-level containers to handle large domains.')]
        [switch]$SplitSearch,

        [Parameter(Mandatory = $false, HelpMessage = 'Splits the search by first letter of CN to handle large domains, if the query fails, will also split the letter.')]
        [switch]$LetterSplitSearch,

        [Parameter(Mandatory = $false, HelpMessage = 'Path to a file containing a list of parsed containers.')]
        [string]$ParsedContainers,

        [Parameter(Mandatory = $false, HelpMessage = 'Recursively process containers that fail.')]
        [switch]$Recurse,

        [Parameter(Mandatory = $false, HelpMessage = 'Enumerate certificates.')]
        [switch]$Certificates,

        [Parameter(Mandatory = $false, HelpMessage = 'Path to state file for checkpoint tracking.')]
        [string]$StateFile,

        [Parameter(Mandatory = $false, HelpMessage = 'Start enumeration from a specific letter or two-letter prefix (max 2 chars).')]
        [ValidateScript({ if ($null -ne $_ -and $_.Length -gt 2) { throw 'StartFromLetter must be maximum 2 characters.' } $true })]
        [string]$StartFromLetter,

        [Parameter(Mandatory = $false, HelpMessage = 'Disable state file functionality.')]
        [switch]$DisableStateFile,

        [Parameter(Mandatory = $false, HelpMessage = 'Keep state file after successful completion.')]
        [switch]$KeepStateFile,

        [Parameter(Mandatory = $false, HelpMessage = 'Display help information.')]
        [switch]$Help
    )

    if ($Help) {
        Print-Help
        return
    }

    if ($Certificates -and ($SplitSearch -or $LetterSplitSearch -or $Recurse -or $ParsedContainers -or $SearchBase)) { 
        Write-Error '[!] Certificate enumeration is done separately from the rest of the enumeration.'
        return
    }

    if (-not $OutputFilePath) {
        Write-Error '[!] -OutputFilePath is required.'
        return
    }

    $parentDir = Split-Path -Path $OutputFilePath -Parent
    if ($parentDir -and -not (Test-Path -Path $parentDir)) {
        Write-Error "[!] The directory for OutputFilePath does not exist: $parentDir"
        return
    }

    if ($StartFromLetter -and -not $LetterSplitSearch) {
        Write-Error '[!] -StartFromLetter requires -LetterSplitSearch to be enabled.'
        return
    }

    if ($ParsedContainers -and -not $SplitSearch) {
        Write-Error '[!] Cannot parse containers if -SplitSearch is not provided.'
        return
    }

    if ($Recurse -and -not $SplitSearch) {
        Write-Error '[!] Cannot recurse if -SplitSearch is not provided.'
        return
    }

    if ($ParsedContainers -and -not (Test-Path -Path $ParsedContainers)) {
        Write-Error '[!] -ParsedContainers path not found, provide a valid path.'
        return
    }


    Print-Logo
    Write-Output '[+] Executing with the following parameters:'
    if ($Server) { Write-Output "   - Server: $Server" }
    Write-Output "   - OutputFilePath: $OutputFilePath"
    if ($LdapFilter) { Write-Output "   - LdapFilter: $LdapFilter" }
    if ($SearchBase) { Write-Output "   - SearchBase: $SearchBase" }
    if ($SplitSearch) { Write-Output '   - SplitSearch enabled' }
    if ($LetterSplitSearch) { Write-Output '   - LetterSplitSearch enabled' }
    if ($Recurse) { Write-Output '   - Recurse enabled' }
    if ($Credential) { Write-Output "   - Credential: $($Credential.UserName)" }
    if ($ParsedContainers) { Write-Output "   - ParsedContainers: $ParsedContainers" }
    if ($StartFromLetter) { Write-Output "   - StartFromLetter: $StartFromLetter" }
    if ($DisableStateFile) { Write-Output '   - StateFile: disabled' } elseif ($StateFile) { Write-Output "   - StateFile: $StateFile" }
    if ($Certificates) { Write-Output '   - Enumerating certificates' }

    


    $count = [ref]0
    $printingThreshold = 1000

    # Prepare Get-ADObject parameters
    $getAdObjectParams = @{
        Properties = '*'
        LdapFilter = $LdapFilter
    }

    if ($Server) { $getAdObjectParams['Server'] = $Server }
    if ($SearchBase) { $getAdObjectParams['SearchBase'] = $SearchBase }
    if ($Credential) { $getAdObjectParams['Credential'] = $Credential }
    if ($PageSize) { $getAdObjectParams['ResultPageSize'] = $PageSize }

    # State file handling
    $stateEnabled = $true
    if ($DisableStateFile) { $stateEnabled = $false }
    $statePath = $null
    if ($stateEnabled) {
        if ($StateFile) { $statePath = $StateFile } else { $statePath = "$OutputFilePath.state.json" }
        $resumeChoice = $null
        if (Test-StateFileExists -Path $statePath) {
            $existingState = Read-StateFile -Path $statePath
            
            # Handle corrupted state file
            if ($null -eq $existingState) {
                Write-Output ''
                Write-Output '[!] WARNING: State file exists but is corrupted or unreadable.'
                Write-Output "[!] Path: $statePath"
                Write-Output ''
                while ($true) {
                    $corruptChoice = Read-Host '[?] Delete corrupted state file and start fresh? [Y]es, [C]ancel'
                    $corruptChoice = $corruptChoice.Trim().ToUpper()
                    if ($corruptChoice -eq 'Y' -or $corruptChoice -eq 'YES') {
                        Write-Output '[+] Deleting corrupted state file and starting fresh...'
                        Remove-StateFile -Path $statePath
                        $stateData = Initialize-StateFile -Path $statePath -Output $OutputFilePath -Server $Server -LdapFilter $LdapFilter -SearchBase $SearchBase -SplitSearch $SplitSearch -LetterSplitSearch $LetterSplitSearch
                        break
                    }
                    elseif ($corruptChoice -eq 'C' -or $corruptChoice -eq 'CANCEL') {
                        Write-Output '[-] Cancelled by user'
                        return
                    }
                    else {
                        Write-Output '[!] Invalid input. Please enter Y or C.'
                    }
                }
            }
            elseif ($existingState['toolMethod'] -and $existingState['toolMethod'] -ne 'ShadowHound-ADM') {
                Write-Output ''
                Write-Output "[!] WARNING: State file was created with $($existingState['toolMethod'])."
                Write-Output '[!] Resuming with ShadowHound-ADM is not possible.'
                Write-Output "[!] Path: $statePath"
                Write-Output ''
                while ($true) {
                    $toolChoice = Read-Host '[?] Delete state file and start fresh? [Y]es, [C]ancel'
                    $toolChoice = $toolChoice.Trim().ToUpper()
                    if ($toolChoice -eq 'Y' -or $toolChoice -eq 'YES') {
                        Write-Output '[+] Deleting state file and starting fresh...'
                        Remove-StateFile -Path $statePath
                        $stateData = Initialize-StateFile -Path $statePath -Output $OutputFilePath -Server $Server -LdapFilter $LdapFilter -SearchBase $SearchBase -SplitSearch $SplitSearch -LetterSplitSearch $LetterSplitSearch
                        break
                    }
                    elseif ($toolChoice -eq 'C' -or $toolChoice -eq 'CANCEL') {
                        Write-Output '[-] Cancelled by user'
                        return
                    }
                    else {
                        Write-Output '[!] Invalid input. Please enter Y or C.'
                    }
                }
            }
            elseif ($existingState['executionMode']) {
                # Check execution mode compatibility
                $currentMode = 'Standard'
                if ($SplitSearch -and $LetterSplitSearch) {
                    $currentMode = 'SplitSearch+LetterSplitSearch'
                }
                elseif ($SplitSearch) {
                    $currentMode = 'SplitSearch'
                }
                elseif ($LetterSplitSearch) {
                    $currentMode = 'LetterSplitSearch'
                }
                
                if ($existingState['executionMode'] -ne $currentMode) {
                    Write-Output ''
                    Write-Output "[!] WARNING: State file execution mode mismatch."
                    Write-Output "[!] State file mode: $($existingState['executionMode'])"
                    Write-Output "[!] Current execution mode: $currentMode"
                    Write-Output '[!] Resuming with mismatched modes will cause data integrity issues.'
                    Write-Output "[!] Path: $statePath"
                    Write-Output ''
                    while ($true) {
                        $modeChoice = Read-Host '[?] Delete state file and start fresh? [Y]es, [C]ancel'
                        $modeChoice = $modeChoice.Trim().ToUpper()
                        if ($modeChoice -eq 'Y' -or $modeChoice -eq 'YES') {
                            Write-Output '[+] Deleting state file and starting fresh...'
                            Remove-StateFile -Path $statePath
                            $stateData = Initialize-StateFile -Path $statePath -Output $OutputFilePath -Server $Server -LdapFilter $LdapFilter -SearchBase $SearchBase -SplitSearch $SplitSearch -LetterSplitSearch $LetterSplitSearch
                            break
                        }
                        elseif ($modeChoice -eq 'C' -or $modeChoice -eq 'CANCEL') {
                            Write-Output '[-] Cancelled by user'
                            return
                        }
                        else {
                            Write-Output '[!] Invalid input. Please enter Y or C.'
                        }
                    }
                }
                else {
                    $resumeChoice = Show-StatePrompt -State $existingState -Path $statePath
                    switch ($resumeChoice) {
                        'Y' { $stateData = $existingState }
                        'N' { Remove-StateFile -Path $statePath; $stateData = Initialize-StateFile -Path $statePath -Output $OutputFilePath -Server $Server -LdapFilter $LdapFilter -SearchBase $SearchBase -SplitSearch $SplitSearch -LetterSplitSearch $LetterSplitSearch }
                        'C' { return }
                        default { $stateData = Initialize-StateFile -Path $statePath -Output $OutputFilePath -Server $Server -LdapFilter $LdapFilter -SearchBase $SearchBase -SplitSearch $SplitSearch -LetterSplitSearch $LetterSplitSearch }
                    }
                }
            }
            else {
                $resumeChoice = Show-StatePrompt -State $existingState -Path $statePath
                switch ($resumeChoice) {
                    'Y' { $stateData = $existingState }
                    'N' { Remove-StateFile -Path $statePath; $stateData = Initialize-StateFile -Path $statePath -Output $OutputFilePath -Server $Server -LdapFilter $LdapFilter -SearchBase $SearchBase -SplitSearch $SplitSearch -LetterSplitSearch $LetterSplitSearch }
                    'C' { return }
                    default { $stateData = Initialize-StateFile -Path $statePath -Output $OutputFilePath -Server $Server -LdapFilter $LdapFilter -SearchBase $SearchBase -SplitSearch $SplitSearch -LetterSplitSearch $LetterSplitSearch }
                }
            }
        }
        else {
            $stateData = Initialize-StateFile -Path $statePath -Output $OutputFilePath -Server $Server -LdapFilter $LdapFilter -SearchBase $SearchBase -SplitSearch $SplitSearch -LetterSplitSearch $LetterSplitSearch
        }
    }

    # Open StreamWriter
    $streamWriter = New-Object System.IO.StreamWriter($OutputFilePath, $true, [System.Text.Encoding]::UTF8)
    try {
        $streamWriter.WriteLine('--------------------')
        if ($Certificates) {

            Write-Output '[*] Getting Configuration Naming Context...'
            $configEnumParams = @{}
            if ($Server) { $configEnumParams['Server'] = $Server }
            if ($Credential) { $configEnumParams['Credential'] = $Credential }
            $configContext = (Get-ADRootDSE @configEnumParams).ConfigurationNamingContext
            if ($null -eq $configContext) {
                Write-Error '[-] Failed to retrieve ConfigurationNamingContext.'
                return
            }

            Write-Output "[*] Enumerating PKI objects under $configContext..."
            $getAdObjectParams['SearchBase'] = $configContext

            $getAdObjectParams['LdapFilter'] = '(objectClass=pKIEnrollmentService)'
            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

            $getAdObjectParams['LdapFilter'] = '(objectClass=pKICertificateTemplate)'
            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

            $getAdObjectParams['LdapFilter'] = '(objectClass=certificationAuthority)'
            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

            $getAdObjectParams['LdapFilter'] = '(objectclass=msPKI-Enterprise-Oid)'
            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

        }
        elseif ($SplitSearch -eq $false -and $LetterSplitSearch -eq $false) {

            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

        }
        elseif ($SplitSearch -eq $true) {
            # Get top-level containers
            Write-Output "[*] Discovering top level containers for $Server..."
            $topLevelContainers = Get-TopLevelContainers -Params $getAdObjectParams
            if ($null -eq $topLevelContainers) {
                Write-Error '[-] Something went wrong, no top-level containers found.'
                return
            }

            # We also need to query specifically the domain object
            $dcSearchParams = @{
                Properties = '*'
                LdapFilter = '(objectClass=domain)'
            }

            if ($Server) { $dcSearchParams['Server'] = $Server }
            if ($Credential) { $dcSearchParams['Credential'] = $Credential }

            Perform-ADQuery -SearchParams $dcSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                        
            # In letter split search we need to make sure the top level containers are included
            if ($LetterSplitSearch -eq $true) {
                $topLevelContainers | ForEach-Object {
                    Process-AdObject -AdObject $_ -StreamWriter $streamWriter
                    $count.Value++
                    if ($count.Value % $printingThreshold -eq 0) {
                        Write-Output "[+] Queried $($Count.Value) objects so far..."
                        $streamWriter.Flush()
                    }
                }


            }


            Write-Output "[+] Found $($topLevelContainers.Count) top-level containers."

            $processedContainers = @()
            $unprocessedContainers = @()

            if ($ParsedContainers) {
                $ParsedContainersList = Get-Content -Path $ParsedContainers
            }
            else {
                $ParsedContainersList = @()
            }

            $isFirstContainer = $true
            foreach ($container in $topLevelContainers) {
                $containerDN = $container.DistinguishedName

                # Skip containers from ParsedContainers file
                if ($ParsedContainersList -contains $containerDN) {
                    Write-Output "[+] Encountered already parsed container $containerDN, skipping..."
                    $processedContainers += $containerDN
                    continue
                }
                
                # Skip already completed containers from state file
                if ($stateEnabled -and $stateData -and $stateData.completedContainers -contains $containerDN) {
                    Write-Output "[+] Container $containerDN already completed, skipping..."
                    $processedContainers += $containerDN
                    continue
                }

                # Check if this container is being retried from a previous failure
                $isContainerRetry = $stateEnabled -and $stateData -and $stateData.failedContainers -and $stateData.failedContainers -contains $containerDN

                $containerSearchParams = $getAdObjectParams.Clone()
                $containerSearchParams['SearchBase'] = $containerDN

                if ($isContainerRetry) {
                    Write-Output "[*] Retrying previously failed container ($($processedContainers.Count + $unprocessedContainers.Count + 1)/$($topLevelContainers.Count)): $containerDN"
                }
                else {
                    Write-Output "[*] Processing container ($($processedContainers.Count + $unprocessedContainers.Count + 1)/$($topLevelContainers.Count)): $containerDN"
                }

                if ($LetterSplitSearch -eq $false) {
                    try {
                        # Process the container
                        Perform-ADQuery -SearchParams $containerSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                        $processedContainers += $containerDN
                        
                        # Checkpoint after successful container query
                        if ($stateEnabled -and $stateData) {
                            $stateData.completedContainers += $containerDN

                            # Remove from failedContainers if it was previously failed (retry success)
                            if ($stateData.failedContainers -and $stateData.failedContainers -contains $containerDN) {
                                $stateData.failedContainers = @($stateData.failedContainers | Where-Object { $_ -ne $containerDN })
                            }

                            $stateData.objectCount = $count.Value
                            Write-StateFile -State $stateData -Path $statePath
                        }
                    }
                    catch {
                        Write-Error "[-] Error processing container '$containerDN': $_"
                        $unprocessedContainers += $containerDN

                        # Persist container failure to state file
                        if ($stateEnabled -and $stateData) {
                            if (-not $stateData.failedContainers) { $stateData.failedContainers = @() }
                            if (-not ($stateData.failedContainers -contains $containerDN)) {
                                $stateData.failedContainers += $containerDN
                            }
                            $stateData.objectCount = $count.Value
                            Write-StateFile -State $stateData -Path $statePath
                        }
                        continue
                    }
                }
                elseif ($LetterSplitSearch -eq $true) {

                    # Split the search by first letter
                    # Top-level charset excludes . and - to avoid garbage queries
                    $charset = ([char[]](97..122) + [char[]](48..57) + '!', '_', '@', '$', '{', '}')
                    # Full charset for 2-letter and 3-letter splits includes . and - for edge cases
                    $charsetFull = $charset + '.', '-'
                    $OriginalFilter = $containerSearchParams['LdapFilter']
                    
                    # Determine starting letter for this container
                    $startIdx = 0
                    if ($stateEnabled -and $stateData -and $stateData.currentContainer -eq $containerDN -and $stateData.completedLetters) {
                        # Resuming this container - use completed letters from state
                        $completedSet = @($stateData.completedLetters)
                    }
                    elseif ($StartFromLetter -and $isFirstContainer) {
                        # User specified starting letter - apply only to first container
                        $completedSet = @()
                        for ($i = 0; $i -lt $charset.Length; $i++) {
                            if ($charset[$i] -eq $StartFromLetter[0]) {
                                $startIdx = $i
                                break
                            }
                        }
                    }
                    else {
                        $completedSet = @()
                    }
                    
                    foreach ($char in $charset[$startIdx..($charset.Length - 1)]) {
                        $charStr = [string]$char
                        
                        # Skip if already completed
                        if ($completedSet -contains $charStr) {
                            Write-Output "  [+] Letter '$charStr' already completed, skipping..."
                            continue
                        }
                        
                        # Check if we have any subletters starting with this letter already completed
                        $hasSubletters = $false
                        foreach ($completed in $completedSet) {
                            if ($completed.Length -eq 2 -and $completed[0] -eq $char) {
                                $hasSubletters = $true
                                break
                            }
                        }
                        
                        # Handle cases where we need to skip single letter and enumerate subletters:
                        # 1. -StartFromLetter with 2-char prefix
                        # 2. We have subletters in completedSet (resume scenario)
                        if (($StartFromLetter -and $StartFromLetter.Length -eq 2 -and $charStr -eq $StartFromLetter[0]) -or $hasSubletters) {
                            $subStartIdx = 0
                            
                            # Determine starting subletter index
                            if ($StartFromLetter -and $StartFromLetter.Length -eq 2 -and $charStr -eq $StartFromLetter[0]) {
                                # User specified a starting subletter
                                for ($i = 0; $i -lt $charset.Length; $i++) {
                                    if ($charset[$i] -eq $StartFromLetter[1]) {
                                        $subStartIdx = $i
                                        break
                                    }
                                }
                                Write-Output "  [*] Starting from double-letter '$StartFromLetter' as requested..."
                            }
                            
                            $subCharset = $charsetFull[$subStartIdx..($charsetFull.Length - 1)]
                            foreach ($subChar in $subCharset) {
                                $doubleChar = "$charStr$subChar"
                                
                                $isRetry = $false
                                if ($stateEnabled -and $stateData -and $stateData.failedLetters[$containerDN] -and $stateData.failedLetters[$containerDN] -contains $doubleChar) {
                                    $isRetry = $true
                                    Write-Output "  [*] Retrying previously failed letter '$doubleChar' for $containerDN"
                                }
                                
                                if (($completedSet -contains $doubleChar) -and -not $isRetry) {
                                    Write-Output "    [+] Letter '$doubleChar' already completed, skipping..."
                                    continue
                                }
                                
                                try {
                                    Write-Output "  [*] Querying $containerDN for objects with CN starting with '$doubleChar'"
                                    $containerSearchParams['LdapFilter'] = "(&$OriginalFilter(cn=$doubleChar**))"
                                    Perform-ADQuery -SearchParams $containerSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                    
                                    # Checkpoint after successful subletter query
                                    if ($stateEnabled -and $stateData) {
                                        if (-not ($stateData.completedLetters -contains $doubleChar)) {
                                            $stateData.completedLetters += $doubleChar
                                        }
                                        
                                        if ($stateData.failedLetters.ContainsKey($containerDN) -and $stateData.failedLetters[$containerDN] -contains $doubleChar) {
                                            $stateData.failedLetters[$containerDN] = @($stateData.failedLetters[$containerDN] | Where-Object { $_ -ne $doubleChar })
                                            if ($stateData.failedLetters[$containerDN].Count -eq 0) {
                                                $stateData.failedLetters.Remove($containerDN)
                                            }
                                        }
                                        
                                        $stateData.currentContainer = $containerDN
                                        $stateData.objectCount = $count.Value
                                        Write-StateFile -State $stateData -Path $statePath
                                    }
                                }
                                catch {
                                    Write-Output "   [-] Failed to process (CN=$doubleChar*) for container '$containerDN': $_`nMoving to the next sub letter..."
                                    
                                    # Track failed letter for this container
                                    if ($stateEnabled -and $stateData) {
                                        if (-not $stateData.failedLetters[$containerDN]) {
                                            $stateData.failedLetters[$containerDN] = @()
                                        }
                                        if ($stateData.failedLetters[$containerDN] -notcontains $doubleChar) {
                                            $stateData.failedLetters[$containerDN] += $doubleChar
                                        }
                                        $stateData.objectCount = $count.Value
                                        Write-StateFile -State $stateData -Path $statePath
                                    }
                                    continue
                                }
                            }
                            continue
                        }
                        
                        Write-Output "  [*] Querying $containerDN for objects with CN starting with '$charStr'"
                        $containerSearchParams['LdapFilter'] = "(&$OriginalFilter(cn=$charStr*))"

                        try {
                            Perform-ADQuery -SearchParams $containerSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                            
                            # Checkpoint after successful query
                            if ($stateEnabled -and $stateData) {
                                $stateData.completedLetters += $charStr
                                $stateData.currentContainer = $containerDN
                                $stateData.objectCount = $count.Value
                                Write-StateFile -State $stateData -Path $statePath
                            }
                        }
                        catch {
                            Write-Output "   [!!] Error processing CN=$charStr* for container '$containerDN': $_`nTrying to split each letter again..."
                            $subCharset = $charset
                            foreach ($subChar in $subCharset) {
                                $doubleChar = "$charStr$subChar"
                                
                                $isRetry = $false
                                if ($stateEnabled -and $stateData -and $stateData.failedLetters[$containerDN] -and $stateData.failedLetters[$containerDN] -contains $doubleChar) {
                                    $isRetry = $true
                                    Write-Output "  [*] Retrying previously failed letter '$doubleChar' for $containerDN"
                                }
                                
                                if (($completedSet -contains $doubleChar) -and -not $isRetry) {
                                    Write-Output "    [+] Letter '$doubleChar' already completed, skipping..."
                                    continue
                                }
                                
                                try {
                                    Write-Output "  [*] Querying $containerDN for objects with CN starting with '$doubleChar'"
                                    $containerSearchParams['LdapFilter'] = "(&$OriginalFilter(cn=$doubleChar*))"
                                    Perform-ADQuery -SearchParams $containerSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                    
                                    # Checkpoint after successful subletter query
                                    if ($stateEnabled -and $stateData) {
                                        if (-not ($stateData.completedLetters -contains $doubleChar)) {
                                            $stateData.completedLetters += $doubleChar
                                        }
                                        
                                        if ($stateData.failedLetters.ContainsKey($containerDN) -and $stateData.failedLetters[$containerDN] -contains $doubleChar) {
                                            $stateData.failedLetters[$containerDN] = @($stateData.failedLetters[$containerDN] | Where-Object { $_ -ne $doubleChar })
                                            if ($stateData.failedLetters[$containerDN].Count -eq 0) {
                                                $stateData.failedLetters.Remove($containerDN)
                                            }
                                        }
                                        
                                        $stateData.currentContainer = $containerDN
                                        $stateData.objectCount = $count.Value
                                        Write-StateFile -State $stateData -Path $statePath
                                    }
                                }
                                catch {
                                    Write-Output "   [-] Failed to process (CN=$doubleChar*) for container '$containerDN': $_`nMoving to the next sub letter..."
                                    
                                    # Track failed letter for this container
                                    if ($stateEnabled -and $stateData) {
                                        if (-not $stateData.failedLetters[$containerDN]) {
                                            $stateData.failedLetters[$containerDN] = @()
                                        }
                                        if ($stateData.failedLetters[$containerDN] -notcontains $doubleChar) {
                                            $stateData.failedLetters[$containerDN] += $doubleChar
                                        }
                                        $stateData.objectCount = $count.Value
                                        Write-StateFile -State $stateData -Path $statePath
                                    }
                                    continue
                                }
                            }
                        }
                    }

                    $processedContainers += $containerDN
                    $isFirstContainer = $false
                    
                    if ($stateEnabled -and $stateData) {
                        $stateData.completedContainers += $containerDN
                        $stateData.completedLetters = @()
                        $stateData.currentContainer = $null
                        Write-StateFile -State $stateData -Path $statePath
                    }
                }
            }

            # Output summary
            Write-Output "Processed $($count.Value) objects in total."
            if ($processedContainers.Count -gt 0) {
                # Silent success
            }
            if ($unprocessedContainers.Count -gt 0) {
                Write-Output "`n[-] Failed to process containers:"
                $unprocessedContainers | ForEach-Object { Write-Output "    - $_" }
            }
            
            # Report failed letters if any
            if ($stateEnabled -and $stateData -and $stateData.failedLetters -and $stateData.failedLetters.Count -gt 0) {
                Write-Output ''
                Write-Output "[!] WARNING: Failed to enumerate letters for the following containers:"
                Write-Output ''
                foreach ($container in $stateData.failedLetters.Keys) {
                    $letters = $stateData.failedLetters[$container] -join ', '
                    Write-Output "  Container: $container"
                    Write-Output "  Failed letters: $letters"
                    Write-Output ''
                }
                Write-Output "[!] Partial or no data written for these letters before failure."
                Write-Output "[!] State file preserved. Resuming will retry failed letters."
                Write-Output ''
                Write-Output "[!] If failures persist, try these manual enumeration strategies:"
                Write-Output ''
                Write-Output "  Option 1 - More specific CN filter using -LdapFilter:"
                Write-Output "    ShadowHound-ADM -Server <server> -SearchBase '<failed-container-DN>' -LdapFilter '(&(objectGuid=*)(cn=2024*))' -OutputFilePath <output>"
                Write-Output "    # Targets specific year instead of broad '20*' pattern"
                Write-Output ''
                Write-Output "  Option 2 - Target a specific sub-OU to reduce scope:"
                Write-Output "    ShadowHound-ADM -Server <server> -SearchBase 'OU=SubOU,<failed-container-DN>' -OutputFilePath <output>"
                Write-Output "    # Enumerate one level deeper to reduce object count per query"
                Write-Output ''
                Write-Output "  Option 3 - Combine filters and letter splitting:"
                Write-Output "    ShadowHound-ADM -Server <server> -SearchBase '<failed-container-DN>' -LdapFilter '(&(objectGuid=*)(cn=202*))' -LetterSplitSearch -OutputFilePath <output>"
                Write-Output "    # Narrow the pattern and still use letter splitting for safety"
                Write-Output ''
            }
        }
        elseif ($LetterSplitSearch -eq $true -and $SplitSearch -eq $false) {
            # Top-level charset excludes . and - to avoid garbage queries
            $charset = ([char[]](97..122) + [char[]](48..57) + '!', '_', '@', '$', '{', '}')
            # Full charset for 2-letter and 3-letter splits includes . and - for edge cases
            $charsetFull = $charset + '.', '-'
            $OriginalFilter = $getAdObjectParams['LdapFilter']
            $globalKey = 'global'
            
            $startIdx = 0
            $completedSet = @()
            if ($stateEnabled -and $stateData -and $stateData.completedLetters) {
                $completedSet = @($stateData.completedLetters)
            }
            elseif ($StartFromLetter) {
                for ($i = 0; $i -lt $charset.Length; $i++) {
                    if ($charset[$i] -eq $StartFromLetter[0]) {
                        $startIdx = $i
                        break
                    }
                }
            }
            
            foreach ($char in $charset[$startIdx..($charset.Length - 1)]) {
                $charStr = [string]$char
                
                # Skip if already completed
                if ($completedSet -contains $charStr) {
                    Write-Output "  [+] Letter '$charStr' already completed, skipping..."
                    continue
                }
                
                # Check if we have any subletters starting with this letter already completed
                $hasSubletters = $false
                foreach ($completed in $completedSet) {
                    if ($completed.Length -eq 2 -and $completed[0] -eq $char) {
                        $hasSubletters = $true
                        break
                    }
                }
                
                # Handle cases where we need to skip single letter and enumerate subletters:
                # 1. -StartFromLetter with 2-char prefix
                # 2. We have subletters in completedSet (resume scenario)
                if (($StartFromLetter -and $StartFromLetter.Length -eq 2 -and $charStr -eq $StartFromLetter[0]) -or $hasSubletters) {
                    $subStartIdx = 0
                    
                    # Determine starting subletter index
                    if ($StartFromLetter -and $StartFromLetter.Length -eq 2 -and $charStr -eq $StartFromLetter[0]) {
                        # User specified a starting subletter
                        for ($i = 0; $i -lt $charset.Length; $i++) {
                            if ($charset[$i] -eq $StartFromLetter[1]) {
                                $subStartIdx = $i
                                break
                            }
                        }
                        Write-Output "  [*] Starting from double-letter '$StartFromLetter' as requested..."
                    }
                    
                    $subCharset = $charsetFull[$subStartIdx..($charsetFull.Length - 1)]
                    foreach ($subChar in $subCharset) {
                        $doubleChar = "$charStr$subChar"
                        $isRetry = $false
                        
                        if ($stateEnabled -and $stateData -and $stateData.failedLetters[$globalKey] -and $stateData.failedLetters[$globalKey] -contains $doubleChar) {
                            $isRetry = $true
                            Write-Output "  [*] Retrying previously failed letter '$doubleChar'"
                        }
                        
                        if (($completedSet -contains $doubleChar) -and -not $isRetry) {
                            Write-Output "    [+] Letter '$doubleChar' already completed, skipping..."
                            continue
                        }
                        
                        $hasTripleLetters = $false
                        foreach ($completed in $completedSet) {
                            if ($completed.Length -eq 3 -and $completed.StartsWith($doubleChar)) {
                                $hasTripleLetters = $true
                                break
                            }
                        }
                        
                        if ($hasTripleLetters) {
                            Write-Output "    [+] Letter '$doubleChar' has 3-letter subletters, iterating those..."
                            
                            # Iterate all 3-letter combinations for this 2-letter prefix
                            foreach ($tripleChar in $charsetFull) {
                                $triplePrefix = "$doubleChar$tripleChar"
                                
                                # Check if already completed
                                if ($completedSet -contains $triplePrefix) {
                                    Write-Output "      [+] Letter '$triplePrefix' already completed, skipping..."
                                    continue
                                }
                                
                                # Check if in failedLetters and needs retry
                                $isFailedRetry = $false
                                if ($stateEnabled -and $stateData -and $stateData.failedLetters[$globalKey] -and $stateData.failedLetters[$globalKey] -contains $triplePrefix) {
                                    $isFailedRetry = $true
                                    Write-Output "      [*] Retrying previously failed letter '$triplePrefix'"
                                }
                                
                                if ($isFailedRetry) {
                                    try {
                                        $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$triplePrefix*))"
                                        Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                        
                                        # Success - add to completed, remove from failed
                                        if ($stateEnabled -and $stateData) {
                                            if (-not ($stateData.completedLetters -contains $triplePrefix)) {
                                                $stateData.completedLetters += $triplePrefix
                                            }
                                            $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $triplePrefix })
                                            if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                                $stateData.failedLetters.Remove($globalKey)
                                            }
                                            $stateData.objectCount = $count.Value
                                            Write-StateFile -State $stateData -Path $statePath
                                        }
                                        Write-Output "      [+] Successfully retried '$triplePrefix'"
                                    }
                                    catch {
                                        Write-Output "      [-] Retry failed for '$triplePrefix': $_"
                                        # Keep in failedLetters for future retry
                                    }
                                }
                            }
                            
                            continue
                        }
                        
                        try {
                            Write-Output "  [*] Querying for objects with CN starting with '$doubleChar'"
                            $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$doubleChar*))"
                            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                            
                            # Checkpoint after successful subletter query
                            if ($stateEnabled -and $stateData) {
                                if (-not ($stateData.completedLetters -contains $doubleChar)) {
                                    $stateData.completedLetters += $doubleChar
                                }
                                
                                if ($stateData.failedLetters.ContainsKey($globalKey) -and $stateData.failedLetters[$globalKey] -contains $doubleChar) {
                                    $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $doubleChar })
                                    if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                        $stateData.failedLetters.Remove($globalKey)
                                    }
                                }
                                
                                $stateData.objectCount = $count.Value
                                Write-StateFile -State $stateData -Path $statePath
                            }
                        }
                        catch {
                            Write-Output "   [-] Failed to process (CN=$doubleChar*): $_"
                            Write-Output '       Trying to split to 3-letter prefixes...'
                            
                            $batchSize = 4
                            $tripleSuccess = $false
                            $failedBatches = @()
                            
                            for ($batchIdx = 0; $batchIdx -lt $charsetFull.Length; $batchIdx += $batchSize) {
                                $batchEnd = [Math]::Min($batchIdx + $batchSize - 1, $charsetFull.Length - 1)
                                $batch = $charsetFull[$batchIdx..$batchEnd]
                                
                                $orFilters = @()
                                foreach ($tripleChar in $batch) {
                                    $triplePrefix = "$doubleChar$tripleChar"
                                    $orFilters += "(cn=$triplePrefix*)"
                                }
                                
                                $batchFilter = "(&$OriginalFilter(|$($orFilters -join '')))"
                                $batchNames = ($batch | ForEach-Object { "$doubleChar$_" }) -join ', '
                                
                                try {
                                    Write-Output "  [*] Querying batch: $batchNames"
                                    $getAdObjectParams['LdapFilter'] = $batchFilter
                                    Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                    $tripleSuccess = $true
                                    
                                    if ($stateEnabled -and $stateData) {
                                        foreach ($tripleChar in $batch) {
                                            $triplePrefix = "$doubleChar$tripleChar"
                                            if (-not ($stateData.completedLetters -contains $triplePrefix)) {
                                                $stateData.completedLetters += $triplePrefix
                                            }

                                            if ($stateData.failedLetters.ContainsKey($globalKey) -and $stateData.failedLetters[$globalKey] -contains $triplePrefix) {
                                                $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $triplePrefix })
                                                if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                                    $stateData.failedLetters.Remove($globalKey)
                                                }
                                            }
                                        }
                                        $stateData.objectCount = $count.Value
                                        Write-StateFile -State $stateData -Path $statePath
                                    }
                                }
                                catch {
                                    Write-Output "   [-] Batch failed - will retry failed batch individually after completing remaining batches"

                                    # Crash-safe: record all triple prefixes in this failed batch for retry.
                                    if ($stateEnabled -and $stateData) {
                                        if (-not $stateData.failedLetters[$globalKey]) {
                                            $stateData.failedLetters[$globalKey] = @()
                                        }
                                        foreach ($tripleChar in $batch) {
                                            $triplePrefix = "$doubleChar$tripleChar"
                                            if ($stateData.failedLetters[$globalKey] -notcontains $triplePrefix) {
                                                $stateData.failedLetters[$globalKey] += $triplePrefix
                                            }
                                        }
                                        $stateData.objectCount = $count.Value
                                        Write-StateFile -State $stateData -Path $statePath
                                    }
                                    $failedBatches += , @($batch)
                                }
                            }
                            
                            foreach ($batch in $failedBatches) {
                                foreach ($tripleChar in $batch) {
                                    $triplePrefix = "$doubleChar$tripleChar"
                                    
                                    try {
                                        Write-Output "  [*] Querying for objects with CN starting with '$triplePrefix'"
                                        $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$triplePrefix*))"
                                        Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                        $tripleSuccess = $true
                                        
                                        if ($stateEnabled -and $stateData) {
                                            if (-not ($stateData.completedLetters -contains $triplePrefix)) {
                                                $stateData.completedLetters += $triplePrefix
                                            }

                                            if ($stateData.failedLetters.ContainsKey($globalKey) -and $stateData.failedLetters[$globalKey] -contains $triplePrefix) {
                                                $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $triplePrefix })
                                                if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                                    $stateData.failedLetters.Remove($globalKey)
                                                }
                                            }
                                            $stateData.objectCount = $count.Value
                                            Write-StateFile -State $stateData -Path $statePath
                                        }
                                    }
                                    catch {
                                        Write-Output "   [-] Failed to process (CN=$triplePrefix*): $_"
                                        
                                        if ($stateEnabled -and $stateData) {
                                            if (-not $stateData.failedLetters[$globalKey]) {
                                                $stateData.failedLetters[$globalKey] = @()
                                            }
                                            if ($stateData.failedLetters[$globalKey] -notcontains $triplePrefix) {
                                                $stateData.failedLetters[$globalKey] += $triplePrefix
                                            }
                                            $stateData.objectCount = $count.Value
                                            Write-StateFile -State $stateData -Path $statePath
                                        }
                                        continue
                                    }
                                }
                            }
                            
                            if ($tripleSuccess -and $stateEnabled -and $stateData) {
                                if ($stateData.failedLetters.ContainsKey($globalKey) -and $stateData.failedLetters[$globalKey] -contains $doubleChar) {
                                    $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $doubleChar })
                                    if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                        $stateData.failedLetters.Remove($globalKey)
                                    }
                                    Write-StateFile -State $stateData -Path $statePath
                                }
                            }
                            elseif (-not $tripleSuccess -and $stateEnabled -and $stateData) {
                                if (-not $stateData.failedLetters[$globalKey]) {
                                    $stateData.failedLetters[$globalKey] = @()
                                }
                                if ($stateData.failedLetters[$globalKey] -notcontains $doubleChar) {
                                    $stateData.failedLetters[$globalKey] += $doubleChar
                                }
                                $stateData.objectCount = $count.Value
                                Write-StateFile -State $stateData -Path $statePath
                            }
                            continue
                        }
                    }
                    continue
                }
                
                Write-Output "  [*] Querying for objects with CN starting with '$charStr'"
                $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$charStr**))"

                try {
                    Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                    
                    # Checkpoint after successful query
                    if ($stateEnabled -and $stateData) {
                        $stateData.completedLetters += $charStr
                        $stateData.objectCount = $count.Value
                        Write-StateFile -State $stateData -Path $statePath
                    }
                }
                catch {
                    Write-Output "   [!!] Error processing character '$charStr*': $_"
                    Write-Output '        Trying to split each letter again...'
                    $subCharset = $charsetFull
                    foreach ($subChar in $subCharset) {
                        $doubleChar = "$charStr$subChar"
                        $isRetry = $false
                        
                        if ($stateEnabled -and $stateData -and $stateData.failedLetters[$globalKey] -and $stateData.failedLetters[$globalKey] -contains $doubleChar) {
                            $isRetry = $true
                            Write-Output "  [*] Retrying previously failed letter '$doubleChar'"
                        }
                        
                        if (($completedSet -contains $doubleChar) -and -not $isRetry) {
                            Write-Output "    [+] Letter '$doubleChar' already completed, skipping..."
                            continue
                        }
                        
                        $hasTripleLetters = $false
                        foreach ($completed in $completedSet) {
                            if ($completed.Length -eq 3 -and $completed.StartsWith($doubleChar)) {
                                $hasTripleLetters = $true
                                break
                            }
                        }
                        
                        if ($hasTripleLetters) {
                            Write-Output "    [+] Letter '$doubleChar' has 3-letter subletters, iterating those..."
                            
                            # Iterate all 3-letter combinations for this 2-letter prefix
                            foreach ($tripleChar in $charsetFull) {
                                $triplePrefix = "$doubleChar$tripleChar"
                                
                                # Check if already completed
                                if ($completedSet -contains $triplePrefix) {
                                    Write-Output "      [+] Letter '$triplePrefix' already completed, skipping..."
                                    continue
                                }
                                
                                # Check if in failedLetters and needs retry
                                $isFailedRetry = $false
                                if ($stateEnabled -and $stateData -and $stateData.failedLetters[$globalKey] -and $stateData.failedLetters[$globalKey] -contains $triplePrefix) {
                                    $isFailedRetry = $true
                                    Write-Output "      [*] Retrying previously failed letter '$triplePrefix'"
                                }
                                
                                if ($isFailedRetry) {
                                    try {
                                        $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$triplePrefix*))"
                                        Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                        
                                        # Success - add to completed, remove from failed
                                        if ($stateEnabled -and $stateData) {
                                            if (-not ($stateData.completedLetters -contains $triplePrefix)) {
                                                $stateData.completedLetters += $triplePrefix
                                            }
                                            $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $triplePrefix })
                                            if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                                $stateData.failedLetters.Remove($globalKey)
                                            }
                                            $stateData.objectCount = $count.Value
                                            Write-StateFile -State $stateData -Path $statePath
                                        }
                                        Write-Output "      [+] Successfully retried '$triplePrefix'"
                                    }
                                    catch {
                                        Write-Output "      [-] Retry failed for '$triplePrefix': $_"
                                        # Keep in failedLetters for future retry
                                    }
                                }
                            }
                            
                            continue
                        }
                        
                        try {
                            Write-Output "  [*] Querying for objects with CN starting with '$doubleChar'"
                            $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$doubleChar**))"
                            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                            
                            # Checkpoint after successful subletter query
                            if ($stateEnabled -and $stateData) {
                                if (-not ($stateData.completedLetters -contains $doubleChar)) {
                                    $stateData.completedLetters += $doubleChar
                                }
                                
                                if ($stateData.failedLetters.ContainsKey($globalKey) -and $stateData.failedLetters[$globalKey] -contains $doubleChar) {
                                    $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $doubleChar })
                                    if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                        $stateData.failedLetters.Remove($globalKey)
                                    }
                                }
                                
                                $stateData.objectCount = $count.Value
                                Write-StateFile -State $stateData -Path $statePath
                            }
                        }
                        catch {
                            Write-Output "   [-] Failed to process (CN=$doubleChar*): $_"
                            Write-Output '       Trying to split to 3-letter prefixes...'
                            
                            $batchSize = 4
                            $tripleSuccess = $false
                            $failedBatches = @()
                            
                            for ($batchIdx = 0; $batchIdx -lt $charsetFull.Length; $batchIdx += $batchSize) {
                                $batchEnd = [Math]::Min($batchIdx + $batchSize - 1, $charsetFull.Length - 1)
                                $batch = $charsetFull[$batchIdx..$batchEnd]
                                
                                $orFilters = @()
                                foreach ($tripleChar in $batch) {
                                    $triplePrefix = "$doubleChar$tripleChar"
                                    $orFilters += "(cn=$triplePrefix*)"
                                }
                                
                                $batchFilter = "(&$OriginalFilter(|$($orFilters -join '')))"
                                $batchNames = ($batch | ForEach-Object { "$doubleChar$_" }) -join ', '
                                
                                try {
                                    Write-Output "  [*] Querying batch: $batchNames"
                                    $getAdObjectParams['LdapFilter'] = $batchFilter
                                    Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                    $tripleSuccess = $true
                                    
                                    if ($stateEnabled -and $stateData) {
                                        foreach ($tripleChar in $batch) {
                                            $triplePrefix = "$doubleChar$tripleChar"
                                            if (-not ($stateData.completedLetters -contains $triplePrefix)) {
                                                $stateData.completedLetters += $triplePrefix
                                            }

                                            if ($stateData.failedLetters.ContainsKey($globalKey) -and $stateData.failedLetters[$globalKey] -contains $triplePrefix) {
                                                $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $triplePrefix })
                                                if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                                    $stateData.failedLetters.Remove($globalKey)
                                                }
                                            }
                                        }
                                        $stateData.objectCount = $count.Value
                                        Write-StateFile -State $stateData -Path $statePath
                                    }
                                }
                                catch {
                                    Write-Output "   [-] Batch failed - will retry failed batch individually after completing remaining batches"

                                    # Crash-safe: record all triple prefixes in this failed batch for retry.
                                    if ($stateEnabled -and $stateData) {
                                        if (-not $stateData.failedLetters[$globalKey]) {
                                            $stateData.failedLetters[$globalKey] = @()
                                        }
                                        foreach ($tripleChar in $batch) {
                                            $triplePrefix = "$doubleChar$tripleChar"
                                            if ($stateData.failedLetters[$globalKey] -notcontains $triplePrefix) {
                                                $stateData.failedLetters[$globalKey] += $triplePrefix
                                            }
                                        }
                                        $stateData.objectCount = $count.Value
                                        Write-StateFile -State $stateData -Path $statePath
                                    }
                                    $failedBatches += , @($batch)
                                }
                            }
                            
                            foreach ($batch in $failedBatches) {
                                foreach ($tripleChar in $batch) {
                                    $triplePrefix = "$doubleChar$tripleChar"
                                    
                                    try {
                                        Write-Output "  [*] Querying for objects with CN starting with '$triplePrefix'"
                                        $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$triplePrefix*))"
                                        Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                        $tripleSuccess = $true
                                        
                                        if ($stateEnabled -and $stateData) {
                                            if (-not ($stateData.completedLetters -contains $triplePrefix)) {
                                                $stateData.completedLetters += $triplePrefix
                                            }

                                            if ($stateData.failedLetters.ContainsKey($globalKey) -and $stateData.failedLetters[$globalKey] -contains $triplePrefix) {
                                                $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $triplePrefix })
                                                if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                                    $stateData.failedLetters.Remove($globalKey)
                                                }
                                            }
                                            $stateData.objectCount = $count.Value
                                            Write-StateFile -State $stateData -Path $statePath
                                        }
                                    }
                                    catch {
                                        Write-Output "   [-] Failed to process (CN=$triplePrefix*): $_"
                                        
                                        if ($stateEnabled -and $stateData) {
                                            if (-not $stateData.failedLetters[$globalKey]) {
                                                $stateData.failedLetters[$globalKey] = @()
                                            }
                                            if ($stateData.failedLetters[$globalKey] -notcontains $triplePrefix) {
                                                $stateData.failedLetters[$globalKey] += $triplePrefix
                                            }
                                            $stateData.objectCount = $count.Value
                                            Write-StateFile -State $stateData -Path $statePath
                                        }
                                        continue
                                    }
                                }
                            }
                            
                            if ($tripleSuccess -and $stateEnabled -and $stateData) {
                                if ($stateData.failedLetters.ContainsKey($globalKey) -and $stateData.failedLetters[$globalKey] -contains $doubleChar) {
                                    $stateData.failedLetters[$globalKey] = @($stateData.failedLetters[$globalKey] | Where-Object { $_ -ne $doubleChar })
                                    if ($stateData.failedLetters[$globalKey].Count -eq 0) {
                                        $stateData.failedLetters.Remove($globalKey)
                                    }
                                    Write-StateFile -State $stateData -Path $statePath
                                }
                            }
                            elseif (-not $tripleSuccess -and $stateEnabled -and $stateData) {
                                if (-not $stateData.failedLetters[$globalKey]) {
                                    $stateData.failedLetters[$globalKey] = @()
                                }
                                if ($stateData.failedLetters[$globalKey] -notcontains $doubleChar) {
                                    $stateData.failedLetters[$globalKey] += $doubleChar
                                }
                                $stateData.objectCount = $count.Value
                                Write-StateFile -State $stateData -Path $statePath
                            }
                            continue
                        }
                    }
                }
            }
            
            if ($stateEnabled -and $stateData -and $stateData.failedLetters -and $stateData.failedLetters.Count -gt 0) {
                Write-Output ''
                Write-Output "[!] WARNING: Failed to enumerate the following letters:"
                if ($stateData.failedLetters[$globalKey]) {
                    $letters = $stateData.failedLetters[$globalKey] -join ', '
                    Write-Output "  Failed letters: $letters"
                }
                Write-Output ''
                Write-Output "[!] Partial or no data written for these letters before failure."
                Write-Output "[!] State file preserved. Resuming will retry failed letters."
                Write-Output ''
                Write-Output "[!] If failures persist, try these manual enumeration strategies:"
                Write-Output ''
                Write-Output "  Option 1 - More specific CN filter using -LdapFilter:"
                Write-Output "    ShadowHound-ADM -Server <server> -SearchBase '<search-base>' -LdapFilter '(&(objectGuid=*)(cn=2024*))' -OutputFilePath <output>"
                Write-Output "    # Targets specific year instead of broad '20*' pattern"
                Write-Output ''
                Write-Output "  Option 2 - Target a specific sub-OU to reduce scope:"
                Write-Output "    ShadowHound-ADM -Server <server> -SearchBase 'OU=SubOU,<search-base>' -OutputFilePath <output>"
                Write-Output "    # Enumerate one level deeper to reduce object count per query"
                Write-Output ''
                Write-Output "  Option 3 - Combine filters and letter splitting:"
                Write-Output "    ShadowHound-ADM -Server <server> -SearchBase '<search-base>' -LdapFilter '(&(objectGuid=*)(cn=202*))' -LetterSplitSearch -OutputFilePath <output>"
                Write-Output "    # Narrow the pattern and still use letter splitting for safety"
                Write-Output ''
            }
        }


        $summaryLine = "Retrieved $($count.Value) results total"
        $streamWriter.WriteLine($summaryLine)
    }
    finally {
        $streamWriter.Flush()
        $streamWriter.Close()
    }

    # State cleanup on completion
    if ($stateEnabled -and $statePath -and -not $KeepStateFile) {
        # Only remove state file if no failures occurred (letter or container)
        $failedContainerCount = if ($stateData -and $stateData.failedContainers) { $stateData.failedContainers.Count } else { 0 }
        $failedLetterCount = if ($stateData -and $stateData.failedLetters) { $stateData.failedLetters.Count } else { 0 }
        $hasFailures = ($failedLetterCount -gt 0) -or ($failedContainerCount -gt 0)

        if ($hasFailures) {
            Write-Output "[*] State file preserved due to failed items ($failedContainerCount containers, $failedLetterCount letters): $statePath"
        }
        else {
            Write-Output '[*] Enumeration complete, removing state file...'
            Remove-StateFile -Path $statePath
        }
    }
    elseif ($stateEnabled -and $KeepStateFile) {
        Write-Output '[*] State file preserved:' $statePath
    }

    Write-Output "Objects have been processed and written to $OutputFilePath"
    Write-Output $summaryLine
    Write-Output '==================================================='


    # Handle recursion if necessary
    if ($Recurse -and $unprocessedContainers.Count -gt 0) {
        Write-Output "[*] Current SearchBase is $SearchBase"
        Write-Output "[*] Attempting to recurse $($unprocessedContainers.Count) failed containers/OUs:"
        foreach ($failedContainer in $unprocessedContainers) {
            Write-Output $failedContainer

            $recurseParams = @{
                OutputFilePath = "$($failedContainer.Split(',')[0].Split('=')[1])_$OutputFilePath"
                SearchBase     = $failedContainer
                SplitSearch    = $true
                Recurse        = $true
            }
            if ($Server) { $recurseParams['Server'] = $Server }
            if ($Credential) { $recurseParams['Credential'] = $Credential }
            if ($ParsedContainers) { $recurseParams['ParsedContainers'] = $ParsedContainers }
            if ($LdapFilter) { $recurseParams['LdapFilter'] = $LdapFilter }

            if ($LetterSplitSearch) {
                $recurseParams['LetterSplitSearch'] = $true
            }


            Write-Output "[+] Attempting to recurse $failedContainer"
            ShadowHound-ADM @recurseParams
        }
    }
}

function Print-Logo {
    $logo = @'
.........................................................................
:  ____  _               _               _   _                       _  :
: / ___|| |__   __ _  __| | _____      _| | | | ___  _   _ _ __   __| | :
: \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_| |/ _ \| | | | '_ \ / _` | :
:  ___) | | | | (_| | (_| | (_) \ V  V /|  _  | (_) | |_| | | | | (_| | :
: |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| |_|\___/ \__,_|_| |_|\__,_| :
:                                                                       :
:   Author: Yehuda Smirnov (X: @yudasm_ BlueSky: @yudasm.bsky.social)   :
.........................................................................
'@
    Write-Output $logo
}

function Print-Help {
    Print-Logo
    $helpMessage = '
ShadowHound-ADM Help

SYNTAX:
    ShadowHound-ADM [-Server <string>] -OutputFilePath <string> [-LdapFilter <string>] [-SearchBase <string>] [-PageSize <int>] [-Credential <pscredential>] [-SplitSearch] [-LetterSplitSearch] [-ParsedContainers <string>] [-Recurse] [-Certificates] [-StateFile <string>] [-StartFromLetter <string>] [-DisableStateFile] [-KeepStateFile] [-Help]

PARAMETERS:
    -Help
        Display help information.

    -Server <string> [Optional]
        The domain controller to query, e.g., domain.local or 192.168.10.10.

    -OutputFilePath <string> [Required]
        The path to the output file where results will be saved.

    -LdapFilter <string> [Optional]
        LDAP filter to customize the search.
        Defaults to (objectGuid=*).

    -SearchBase <string> [Optional]
        The base DN for the search, e.g., CN=top,CN=level,DC=domain,DC=local.
        Defaults to the root of the domain.

    -PageSize <int> [Optional]
        The number of objects to include in one page for paging LDAP searches.

    -Credential <pscredential> [Optional]
        PSCredential object for alternate credentials.

    -SplitSearch [Optional]
        Splits the search across top-level containers to handle large domains.

    -LetterSplitSearch [Optional]
        Splits the search by first letter of CN to handle large domains; if the query fails, will also split the letter.

    -ParsedContainers <string> [Optional]
        Path to a file containing a newline-separated list of Distinguished Names of parsed containers (exact match required).

    -Certificates [Optional]
        Enumerate certificates.

    -Recurse [Optional]
        Recursively process containers that fail.

    -StateFile <string> [Optional]
        Path to state file for checkpoint tracking.
        If not specified, defaults to <OutputFilePath>.state.json.

    -StartFromLetter <string> [Optional]
        Start enumeration from a specific letter (max 2 chars).
        Examples: "d", "ah", "@"
        Skips all letters before the specified starting point.

    -DisableStateFile [Optional]
        Disable state file functionality entirely.
        No checkpoints created, no resume capability.

    -KeepStateFile [Optional]
        Preserve state file after successful completion.
        By default, state file is automatically deleted on completion.

EXAMPLES:
    # Example 1: Basic usage with required parameter
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt"

    # Example 2: Specify a domain controller and custom LDAP filter
    ShadowHound-ADM -Server "dc.domain.local" -OutputFilePath "C:\Results\output.txt" -LdapFilter "(objectClass=user)"

    # Example 3: Use alternate credentials and specify a search base
    $cred = Get-Credential
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -Credential $cred -SearchBase "DC=domain,DC=local"

    # Example 4: Split the search across top-level containers with split letter search
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -SplitSearch -LetterSplitSearch

    # Example 5: Enumerate certificates
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -Certificates

    # Example 6: Resume after interruption (auto-detects state file)
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -LetterSplitSearch

    # Example 7: Start from specific letter
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -LetterSplitSearch -StartFromLetter "m"

    # Example 8: Disable state file for zero artifacts
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -LetterSplitSearch -DisableStateFile
'
    Write-Host $helpMessage
    return
}

function Process-AdObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADObject]$AdObject,

        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$StreamWriter
    )

    # Define ignored properties
    $ignoredValues = @(
        'CanonicalName', 'PropertyNames', 'AddedProperties', 'RemovedProperties',
        'ModifiedProperties', 'PropertyCount', 'repsTo', 'ProtectedFromAccidentalDeletion',
        'sDRightsEffective', 'modifyTimeStamp', 'Modified', 'createTimeStamp',
        'Created', 'userCertificate'
    )

    # Map object classes
    $objectClassMapping = @{
        'applicationSettings'                  = 'top, applicationSettings, nTFRSSettings'
        'builtinDomain'                        = 'top, builtinDomain'
        'classStore'                           = 'top, classStore'
        'container'                            = 'top, container'
        'groupPolicyContainer'                 = 'top, container, groupPolicyContainer'
        'msImaging-PSPs'                       = 'top, container, msImaging-PSPs'
        'rpcContainer'                         = 'top, container, rpcContainer'
        'dfsConfiguration'                     = 'top, dfsConfiguration'
        'dnsNode'                              = 'top, dnsNode'
        'dnsZone'                              = 'top, dnsZone'
        'domainDNS'                            = 'top, domain, domainDNS'
        'fileLinkTracking'                     = 'top, fileLinkTracking'
        'linkTrackObjectMoveTable'             = 'top, fileLinkTracking, linkTrackObjectMoveTable'
        'linkTrackVolumeTable'                 = 'top, fileLinkTracking, linkTrackVolumeTable'
        'foreignSecurityPrincipal'             = 'top, foreignSecurityPrincipal'
        'group'                                = 'top, group'
        'infrastructureUpdate'                 = 'top, infrastructureUpdate'
        'ipsecFilter'                          = 'top, ipsecBase, ipsecFilter'
        'ipsecISAKMPPolicy'                    = 'top, ipsecBase, ipsecISAKMPPolicy'
        'ipsecNegotiationPolicy'               = 'top, ipsecBase, ipsecNegotiationPolicy'
        'ipsecNFA'                             = 'top, ipsecBase, ipsecNFA'
        'ipsecPolicy'                          = 'top, ipsecBase, ipsecPolicy'
        'domainPolicy'                         = 'top, leaf, domainPolicy'
        'secret'                               = 'top, leaf, secret'
        'trustedDomain'                        = 'top, leaf, trustedDomain'
        'lostAndFound'                         = 'top, lostAndFound'
        'msDFSR-Content'                       = 'top, msDFSR-Content'
        'msDFSR-ContentSet'                    = 'top, msDFSR-ContentSet'
        'msDFSR-GlobalSettings'                = 'top, msDFSR-GlobalSettings'
        'msDFSR-LocalSettings'                 = 'top, msDFSR-LocalSettings'
        'msDFSR-Member'                        = 'top, msDFSR-Member'
        'msDFSR-ReplicationGroup'              = 'top, msDFSR-ReplicationGroup'
        'msDFSR-Subscriber'                    = 'top, msDFSR-Subscriber'
        'msDFSR-Subscription'                  = 'top, msDFSR-Subscription'
        'msDFSR-Topology'                      = 'top, msDFSR-Topology'
        'msDS-PasswordSettingsContainer'       = 'top, msDS-PasswordSettingsContainer'
        'msDS-QuotaContainer'                  = 'top, msDS-QuotaContainer'
        'msTPM-InformationObjectsContainer'    = 'top, msTPM-InformationObjectsContainer'
        'organizationalUnit'                   = 'top, organizationalUnit'
        'contact'                              = 'top, person, organizationalPerson, contact'
        'user'                                 = 'top, person, organizationalPerson, user'
        'computer'                             = 'top, person, organizationalPerson, user, computer'
        'rIDManager'                           = 'top, rIDManager'
        'rIDSet'                               = 'top, rIDSet'
        'samServer'                            = 'top, securityObject, samServer'
        'msExchSystemObjectsContainer'         = 'top, container, msExchSystemObjectsContainer'
        'msRTCSIP-ApplicationContacts'         = 'top, container, msRTCSIP-ApplicationContacts'
        'msRTCSIP-ArchivingServer'             = 'top, container, msRTCSIP-ArchivingServer'
        'msRTCSIP-ConferenceDirectories'       = 'top, container, msRTCSIP-ConferenceDirectories'
        'msRTCSIP-ConferenceDirectory'         = 'top, container, msRTCSIP-ConferenceDirectory'
        'msRTCSIP-Domain'                      = 'top, container, msRTCSIP-Domain'
        'msRTCSIP-EdgeProxy'                   = 'top, container, msRTCSIP-EdgeProxy'
        'msRTCSIP-GlobalContainer'             = 'top, container, msRTCSIP-GlobalContainer'
        'msRTCSIP-GlobalTopologySetting'       = 'top, container, msRTCSIP-GlobalTopologySetting'
        'msRTCSIP-GlobalTopologySettings'      = 'top, container, msRTCSIP-GlobalTopologySettings'
        'msRTCSIP-GlobalUserPolicy'            = 'top, container, msRTCSIP-GlobalUserPolicy'
        'msRTCSIP-LocalNormalization'          = 'top, container, msRTCSIP-LocalNormalization'
        'msRTCSIP-LocalNormalizations'         = 'top, container, msRTCSIP-LocalNormalizations'
        'msRTCSIP-LocationContactMapping'      = 'top, container, msRTCSIP-LocationContactMapping'
        'msRTCSIP-LocationContactMappings'     = 'top, container, msRTCSIP-LocationContactMappings'
        'msRTCSIP-LocationProfile'             = 'top, container, msRTCSIP-LocationProfile'
        'msRTCSIP-LocationProfiles'            = 'top, container, msRTCSIP-LocationProfiles'
        'msRTCSIP-MCUFactories'                = 'top, container, msRTCSIP-MCUFactories'
        'msRTCSIP-MCUFactory'                  = 'top, container, msRTCSIP-MCUFactory'
        'msRTCSIP-MonitoringServer'            = 'top, container, msRTCSIP-MonitoringServer'
        'msRTCSIP-PhoneRoute'                  = 'top, container, msRTCSIP-PhoneRoute'
        'msRTCSIP-PhoneRoutes'                 = 'top, container, msRTCSIP-PhoneRoutes'
        'msRTCSIP-Policies'                    = 'top, container, msRTCSIP-Policies'
        'msRTCSIP-Pool'                        = 'top, container, msRTCSIP-Pool'
        'msRTCSIP-Pools'                       = 'top, container, msRTCSIP-Pools'
        'msRTCSIP-RouteUsage'                  = 'top, container, msRTCSIP-RouteUsage'
        'msRTCSIP-RouteUsages'                 = 'top, container, msRTCSIP-RouteUsages'
        'msRTCSIP-TrustedMCU'                  = 'top, container, msRTCSIP-TrustedMCU'
        'msRTCSIP-TrustedMCUs'                 = 'top, container, msRTCSIP-TrustedMCUs'
        'msRTCSIP-TrustedProxies'              = 'top, container, msRTCSIP-TrustedProxies'
        'msRTCSIP-TrustedServer'               = 'top, container, msRTCSIP-TrustedServer'
        'msRTCSIP-TrustedService'              = 'top, container, msRTCSIP-TrustedService'
        'msRTCSIP-TrustedServices'             = 'top, container, msRTCSIP-TrustedServices'
        'msRTCSIP-TrustedWebComponentsServer'  = 'top, container, msRTCSIP-TrustedWebComponentsServer'
        'msRTCSIP-TrustedWebComponentsServers' = 'top, container, msRTCSIP-TrustedWebComponentsServers'
        'msWMI-Som'                            = 'top, msWMI-Som'
        'nTFRSReplicaSet'                      = 'top, nTFRSReplicaSet'
        'packageRegistration'                  = 'top, packageRegistration'
        'msDS-GroupManagedServiceAccount'      = 'top, person, organizationalPerson, user, computer, msDS-GroupManagedServiceAccount'
        'pKIEnrollmentService'                 = 'top, pKIEnrollmentService'
        'nTFRSSettings'                        = 'top, applicationSettings, nTFRSSettings'
        'rpcServer'                            = 'top, leaf, connectionPoint, rpcEntry, rpcServer'
        'rpcServerElement'                     = 'top, leaf, connectionPoint, rpcEntry, rpcServerElement'
        'serviceConnectionPoint'               = 'top, leaf, connectionPoint, serviceConnectionPoint'
        'msRTCSIP-ApplicationServerService'    = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-ApplicationServerService'
        'msRTCSIP-MCUFactoryService'           = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-MCUFactoryService'
        'msRTCSIP-PoolService'                 = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-PoolService'
        'msRTCSIP-Service'                     = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-Service'
        'msRTCSIP-WebComponentsService'        = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-WebComponentsService'
        'pKICertificateTemplate'               = 'top, pKICertificateTemplate'
        'certificationAuthority'               = 'top, certificationAuthority'
        'msPKI-Enterprise-Oid'                 = 'top, msPKI-Enterprise-Oid'
    }

    if ($null -eq $AdObject) {
        Write-Error 'AdObject is null'
        return
    }

    $outputLines = New-Object System.Collections.Generic.List[string]
    $outputLines.Add('--------------------')

    foreach ($property in $AdObject.PSObject.Properties) {
        $name = $property.Name
        $value = $property.Value

        # Skip properties with empty values and unwanted properties
        if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) -or $ignoredValues -contains $name) {
            continue
        }

        # Cache type checks
        $isDateTime = $value -is [datetime]
        $isByteArray = $value -is [byte[]]
        $isGuid = $value -is [guid]
        $isCollection = $value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]

        switch ($name) {
            'nTSecurityDescriptor' {
                if ($null -ne $value) {
                    $binaryForm = $value.GetSecurityDescriptorBinaryForm()
                    if ($binaryForm.Length -gt 0) {
                        $base64Value = [System.Convert]::ToBase64String($binaryForm)
                        $outputLines.Add("$name`: $base64Value")
                    }
                }
                break
            }
            'objectClass' {
                if ($objectClassMapping.ContainsKey($value)) {
                    $formattedObjectClass = $objectClassMapping[$value]
                }
                else {
                    $formattedObjectClass = ($value -join ', ')
                }
                $outputLines.Add("$name`: $formattedObjectClass")
                break
            }
            default {
                if ($isDateTime) {
                    # Format date/time attributes in LDAP time format
                    $formattedValue = '{0:yyyyMMddHHmmss.0Z}' -f $value.ToUniversalTime()
                    $outputLines.Add("$name`: $formattedValue")
                }
                elseif ($isByteArray) {
                    # Base64 encode byte arrays
                    if ($value.Length -gt 0) {
                        $base64Value = [System.Convert]::ToBase64String($value)
                        $outputLines.Add("$name`: $base64Value")
                    }
                }
                elseif ($isGuid) {
                    $outputLines.Add("$name`: $value")
                }
                elseif ($isCollection) {
                    switch ($name) {
                        'dSCorePropagationData' {
                            # Efficiently find the latest date
                            $latestDate = $null
                            foreach ($date in $value) {
                                if ($date -is [datetime]) {
                                    if ($null -eq $latestDate -or $date -gt $latestDate) {
                                        $latestDate = $date
                                    }
                                }
                            }
                            if ($null -ne $latestDate) {
                                $formattedDate = '{0:yyyyMMddHHmmss.0Z}' -f $latestDate.ToUniversalTime()
                                $outputLines.Add("$name`: $formattedDate")
                            }
                            break
                        }
                        'cACertificate' {
                            if ($value.Count -gt 0 -and $value[0].Length -gt 0) {
                                $base64Value = [System.Convert]::ToBase64String($value[0])
                                $outputLines.Add("$name`: $base64Value")
                            }
                            break
                        }
                        'userCertificate' {
                            if ($value.Count -gt 0 -and $value[0].Length -gt 0) {
                                $base64Value = [System.Convert]::ToBase64String($value[0])
                                $outputLines.Add("$name`: $base64Value")
                            }
                            break
                        }
                        'authorityRevocationList' {
                            $outputLines.Add("$name`: $null")
                            break
                        }
                        default {
                            $joinedValues = ($value | ForEach-Object { $_.ToString() }) -join ', '
                            $outputLines.Add("$name`: $joinedValues")
                            break
                        }
                    }
                }
                else {
                    # General handling for other types
                    $outputLines.Add("$name`: $value")
                }
                break
            }
        }
    }

    # Write the formatted content to the file using StreamWriter
    foreach ($line in $outputLines) {
        $StreamWriter.WriteLine($line)
    }
}

function Perform-ADQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$SearchParams,

        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$StreamWriter,

        [Parameter(Mandatory = $true)]
        [ref]$Count,

        [Parameter(Mandatory = $false)]
        [int]$PrintingThreshold = 1000
    )

    $SearchParams['ResultSetSize'] = 100000

    Get-ADObject @SearchParams | ForEach-Object {
        Process-AdObject -AdObject $_ -StreamWriter $StreamWriter
        $Count.Value++
        if ($Count.Value % $PrintingThreshold -eq 0) {
            Write-Output "      [**] Queried $($Count.Value) objects so far..."
        }
    }
    
    $StreamWriter.Flush()
}

function Get-TopLevelContainers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Params
    )

    try {
        $topLevelParams = $Params.Clone()
        $topLevelParams['SearchScope'] = 'OneLevel'
        $TopLevelContainers = Get-ADObject @topLevelParams 
        return $TopLevelContainers
    }
    catch {
        Write-Error "Failed to retrieve top-level containers: $_"
        return $null
    }
}

function Initialize-StateFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Output,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [string]$LdapFilter,

        [Parameter(Mandatory = $false)]
        [string]$SearchBase,

        [Parameter(Mandatory = $false)]
        [bool]$SplitSearch = $false,

        [Parameter(Mandatory = $false)]
        [bool]$LetterSplitSearch = $false
    )

    # Determine execution mode
    $mode = 'Standard'
    if ($SplitSearch -and $LetterSplitSearch) {
        $mode = 'SplitSearch+LetterSplitSearch'
    }
    elseif ($SplitSearch) {
        $mode = 'SplitSearch'
    }
    elseif ($LetterSplitSearch) {
        $mode = 'LetterSplitSearch'
    }

    $state = @{
        version             = '1.0'
        toolMethod          = 'ShadowHound-ADM'
        timestamp           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        outputFile          = $Output
        executionMode       = $mode
        ldapFilter          = if ($LdapFilter) { $LdapFilter } else { '(objectGuid=*)' }
        completedContainers = @()
        failedContainers    = @()
        completedLetters    = @()
        failedLetters       = @{}
        objectCount         = 0
    }

    if ($Server) { $state.server = $Server }
    if ($SearchBase) { $state.searchBase = $SearchBase }

    return $state
}

function Test-StateFileExists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Test-Path -Path $Path -PathType Leaf)
}

function Read-StateFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $json = Get-Content -Path $Path -Raw -ErrorAction Stop
        $psobject = $json | ConvertFrom-Json -ErrorAction Stop
        
        $state = @{}
        $psobject.PSObject.Properties | ForEach-Object {
            $name = $_.Name
            $value = $_.Value
            
            if ($value -is [PSCustomObject]) {
                $nested = @{}
                $value.PSObject.Properties | ForEach-Object {
                    $nested[$_.Name] = $_.Value
                }
                $state[$name] = $nested
            }
            else {
                $state[$name] = $value
            }
        }
        
        return $state
    }
    catch {
        return $null
    }
}

function Write-StateFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $State.timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $json = $State | ConvertTo-Json -Depth 10
        
        # Custom compaction for letters only
        try {
            # specific regex to compact completedLetters and failedLetters values only
            $json = [regex]::Replace($json, '(?ms)"(completedLetters|failedLetters)":\s*\[(.*?)\]', {
                    param($match)
                    $key = $match.Groups[1].Value
                    $content = $match.Groups[2].Value
                    # Compact the array content
                    $compacted = $content -replace '\s+', ''
                    "`"$key`": [$compacted]"
                })
        }
        catch {
            # Regex failed, use formatted JSON
        }

        
        $json | Set-Content -Path $Path -Force -ErrorAction Stop
    }
    catch {
        Write-Error "[-] Failed to write state file: $_"
    }
}

function Remove-StateFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -Path $Path) {
        try {
            Remove-Item -Path $Path -Force -ErrorAction Stop
        }
        catch {
            Write-Error "[-] Failed to remove state file: $_"
        }
    }
}

function Show-StatePrompt {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $State,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    [Console]::WriteLine('')
    [Console]::WriteLine('[*] Found existing state file: ' + $Path)
    [Console]::WriteLine('[*] Last checkpoint:')
    
    $containers = $State['completedContainers']
    if ($containers -and $containers.Count -gt 0) {
        [Console]::WriteLine("    - Completed containers: $($containers.Count)")
    }
    
    $currentContainer = $State['currentContainer']
    if ($currentContainer) {
        [Console]::WriteLine("    - Current container: $currentContainer")
    }
    
    $letters = $State['completedLetters']
    if ($letters -and $letters.Count -gt 0) {
        $letterList = $letters -join ', '
        if ($currentContainer) {
            [Console]::WriteLine("    - Completed letters (in current container): $letterList")
        }
        else {
            [Console]::WriteLine("    - Completed letters: $letterList")
        }
    }
    elseif ($currentContainer) {
        [Console]::WriteLine('    - Completed letters (in current container): (none yet)')
    }
    else {
        [Console]::WriteLine('    - Completed letters: (none yet)')
    }
    
    $objCount = $State['objectCount']
    if ($objCount -and $objCount -gt 0) {
        [Console]::WriteLine("    - Objects enumerated: $objCount")
    }
    
    $failedContainers = $State['failedContainers']
    if ($failedContainers -and $failedContainers.Count -gt 0) {
        [Console]::WriteLine('')
        [Console]::WriteLine('[!] Failed containers detected (will be retried on resume):')
        foreach ($fc in $failedContainers) {
            [Console]::WriteLine("    - $fc")
        }
    }

    $failedLetters = $State['failedLetters']
    if ($failedLetters -and $failedLetters.Count -gt 0) {
        [Console]::WriteLine('')
        [Console]::WriteLine('[!] Failed letters detected (will be retried on resume):')
        foreach ($container in $failedLetters.Keys) {
            $letters = $failedLetters[$container] -join ', '
            [Console]::WriteLine("    Container: $container")
            [Console]::WriteLine("    Letters: $letters")
        }
    }
    
    $timestamp = $State['timestamp']
    if ($timestamp) {
        [Console]::WriteLine("    - Timestamp: $timestamp")
    }
    
    [Console]::WriteLine('')
    [Console]::WriteLine('[!] Note: Resuming will append to existing output file')
    [Console]::WriteLine('')

    while ($true) {
        $choice = Read-Host '[?] Resume from checkpoint? [Y]es, [N]o, [C]ancel'
        $choice = $choice.Trim().ToUpper()
        
        if ($choice -eq 'Y' -or $choice -eq 'YES') {
            [Console]::WriteLine('[+] Resuming from checkpoint...')
            return 'Y'
        }
        elseif ($choice -eq 'N' -or $choice -eq 'NO') {
            [Console]::WriteLine('[+] Starting fresh enumeration...')
            return 'N'
        }
        elseif ($choice -eq 'C' -or $choice -eq 'CANCEL') {
            [Console]::WriteLine('[-] Cancelled by user')
            return 'C'
        }
        else {
            [Console]::WriteLine('[!] Invalid input. Please enter Y, N, or C.')
        }
    }
}
