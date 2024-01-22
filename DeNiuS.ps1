#Requires -Version 7 
function Get-DNSData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = 'File', Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)][Alias('PSPath')][ValidateNotNullOrEmpty()][string[]]$Inputfile,
        [Parameter(Mandatory, ParameterSetName = 'Object', Position = 0, ValueFromPipeline)][ValidateNotNullOrEmpty()][string[]]$Inputobject,
        [Switch]$Exportdata,
        [Switch]$Extendedtypes
    )

    begin {
        # Setup of objects and threads
        if ($inputfile) { $inputdata = Get-Content (Resolve-Path $inputfile) } else { $inputdata = $inputobject }
        if ($exportdata) { $Folder = New-Item -Path .\DeNius_$(Get-Date -Format FileDateTime) -ItemType Directory }
        $unsorted = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
        $count = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
        $threads = $([int]$env:NUMBER_OF_PROCESSORS) * 4
        $total = $inputdata.count

        # Art makes it better / I'm a real boy.
        Clear-Host 
        Write-Host -Foregroundcolor Red "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄`n██░▄▄▀█░▄▄██░▀██░██▄██░██░██░▄▄▄░████████▄▄░▄▄█░████░▄▄████░▄▄▀██░▀██░██░▄▄▄░████░▄▄▀█░▄▄█░▄▄█▀▄▄▀█░██▀███▀█░▄▄█░▄▄▀█`n██░██░█░▄▄██░█░█░██░▄█░██░██▄▄▄▀▀███▄▄█████░███░▄▄░█░▄▄████░██░██░█░█░██▄▄▄▀▀████░▀▀▄█░▄▄█▄▄▀█░██░█░███░▀░██░▄▄█░▀▀▄█`n██░▀▀░█▄▄▄██░██▄░█▄▄▄██▄▄▄██░▀▀▀░██████████░███▄██▄█▄▄▄████░▀▀░██░██▄░██░▀▀▀░████░██░█▄▄▄█▄▄▄██▄▄██▄▄███▄███▄▄▄█▄█▄▄█`n▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀`n----------------------------------------------------------------------------------------------------------------------`nPlease wait whilst I resolve the input data, patience is a virtue.`n----------------------------------------------------------------------------------------------------------------------"
    }

    process {
        Write-Host -BackgroundColor DarkGray "`nStarting Resolution....`n"
        if ($Extendedtypes) { Write-Host -BackgroundColor Blue "`n You Selected All DNS Types, this may be slow...`n" }
        # Starts multiple threadjobs, then adds concurrent bag items to each instance (1) and resolves IP (2), then otionally other types of data (3) for inputdata or inputlist of DNS names, then finally adds them to unsorted object (4)
        $inputdata | ForEach-Object -ThrottleLimit $threads -AsJob -Parallel {
            #(1)
            $unsorted = $Using:unsorted
            $count = $using:count
            $extendedtypes = $using:extendedtypes
            #(2)
            $dns = [System.Net.DNS]::GetHostEntryAsync($_).Result
            if ($null -eq $dns) { $count.add($_); Continue } else {
                $item = [PSCustomObject]@{
                    ID          = $null
                    Name        = $_
                    IPAddresses = $dns.AddressList.IPAddressToString
                }
            }
            if ($_ -notmatch $dns.HostName) { Add-Member -InputObject $item -NotePropertyName 'CName' -NotePropertyValue $dns.HostName -Force }
            $rdns = $item.ipaddresses.foreach({ [System.Net.DNS]::GetHostEntry($_) }).HostName.where({ $_ -notmatch $item.name })
            if ($rdns) { Add-Member -InputObject $item -NotePropertyName 'ReverseDNS' -NotePropertyValue $rdns }
            #(3)
            if ($extendedtypes) {
                $TXTrecs = Resolve-DnsName -Type TXT -Name $_
                $SRVrecs = (Resolve-DnsName -Type SRV -Name $_).where({ $_.section -eq 'Answer' -and $_.Type -eq 'SRV' })
                $MXrecs = $('MX', 'MF', 'MR', 'MG', 'MB', 'MINFO', 'RP').foreach({ Resolve-DnsName -Type $_ $item.name -DnsOnly -NoHostsFile -QuickTimeout })
                $DNSSecrecs = $('RRSIG', 'NSEC', 'DNSKEY', 'NSEC3', 'NSEC3PARAM').foreach({ Resolve-DNSName -DNSOnly -TcpOnly -DnssecOk -NoHostsFile -QuickTimeout -Type $_ $item.Name }).Where({ $_.Section -eq 'Answer' })
                $Miscrecs = ('MD', 'WKS', 'AFSDB', 'X25', 'ISDN', 'RT', 'DNAME', 'DS', 'DHCID', 'ANY', 'All', 'Unknown').foreach({ Resolve-DNSName -DNSOnly -TcpOnly -DnssecOk -NoHostsFile -QuickTimeout -Type $_ $item.Name }).Where({ $_.type -ne 'RRSIG' -and $_.type -ne 'NSEC' -and $_.type -ne 'DNSKEY' -and $_.type -ne 'NSEC3' -and $_.type -ne 'NSEC3PARAM' -and $_.type -ne 'RRSIG' -and $_.type -ne 'NSEC' -and $_.type -ne 'DNSKEY' -and $_.type -ne 'NSEC3' -and $_.type -ne 'NSEC3PARAM' -and $_.type -ne 'NS' -and $_.type -ne 'OPt' -and $_.type -ne 'HINFO' -and $_.type -ne 'SOA' -and $_.type -ne 'TXT' -and $_.type -ne 'MX' -and $_.type -ne 'MX' -and $_.type -ne 'MR' -and $_.type -ne 'MG' -and $_.type -ne 'MB' -and $_.type -ne 'MINFO' -and $_.type -ne 'RP' -and $_.type -ne 'SRV' -and $_.type -ne 'A' -and $_.type -ne 'AAAA' -and $_.type -ne 'CNAME' -and $_.type -ne 'PTR' }) | Sort-Object -Unique -Property Type
                if ($TXTrecs.strings) { Add-Member -InputObject $item -NotePropertyName 'TXTrecs' -NotePropertyValue $TXTrecs.strings }
                if ($SRVrecs) { Add-Member -InputObject $item -NotePropertyName 'SRVrecs' -NotePropertyValue ($SRVrecs | Select-Object NameTarget, Port | Format-Table -HideTableHeaders | Out-String -Stream | Select-Object -Skip 1 -SkipLast 1) }
                if ($MXrecs) { Add-Member -InputObject $item -NotePropertyName 'MXRecs' -NotePropertyValue $($MXrecs | Select-Object -Property Name* -ExcludeProperty Name | Format-Table -HideTableHeaders | Out-String -Stream | Select-Object -Skip 1) }
                if ($DNSsecrecs) { Add-Member -InputObject $item -NotePropertyName 'DNSSECRecs' -NotePropertyValue $DNSSecrecs }
                if ($Miscrecs) { Add-Member -InputObject $item -NotePropertyName 'MiscRecs' -NotePropertyValue $Miscrecs }
            }
            #(4)
            $unsorted.Add($item)
            $count.add($null)

        } | Out-Null
        
        # Progress bar w/ completion
        while (Get-Job -State Running, NotStarted) {
            $comppc = $count.count / $total * 100
            Write-Progress -Activity 'Obtaining DNS Data' -Status "$($count.Count) checked : $comppc% Complete " -PercentComplete $comppc
        }

        # Export to global object and add ID's
        $Global:DeNiuS = $unsorted | Sort-Object -Property Name, IPAddresses, CName, ReverseDNS
        $ID = 0
        $DeNiuS.foreach({
                $_.id = $id
                $id++
            })
    }
    
    end {
        # Export data to xml and json
        if ($exportdata) {
            Write-Host "`nExporting Data to: $($folder.FullName)"
            Export-Clixml -InputObject $DeNiuS -Path $("$($Folder.FullName)" + '\DeniusCLIXML.XML')
            ConvertTo-Json -InputObject $DeNiuS -Compress -Depth 10 | Out-File -Path $("$($Folder.FullName)" + '\DeniusJson.JSON')
        }
        Write-Host -ForegroundColor Green "`nAll Done - Happy Hunting! `n>>> All data will be exported to the `$DeNiuS variable"
        Write-host -Foregroundcolor Red "`n----------------------------------------------------------------------------------------------------------------------"
    }
}
