/*
    Larvanex bundled YARA rules
    ---------------------------
    Small, readable rules that demonstrate the YARA engine. They match on
    behavioural markers, not on working malicious code. Extend freely, or point
    Larvanex at your own rule directory with --yara PATH.
*/

rule Larvanex_PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell invoked with an encoded command"
        severity = "high"
        attack = "T1059.001,T1140"
    strings:
        $ps = "powershell" nocase ascii wide
        $enc = "-encodedcommand" nocase ascii wide
        $enc_short = "-enc " nocase ascii wide
    condition:
        $ps and ($enc or $enc_short)
}

rule Larvanex_LOLBin_Certutil
{
    meta:
        description = "certutil abused to download or decode a remote file"
        severity = "high"
        attack = "T1105,T1140"
    strings:
        $certutil = "certutil" nocase
        $urlcache = "urlcache" nocase
        $decode = "decode" nocase
    condition:
        $certutil and ($urlcache or $decode)
}

rule Larvanex_PDF_Auto_JavaScript
{
    meta:
        description = "PDF with an automatic JavaScript action"
        severity = "high"
        attack = "T1059.007,T1204.002"
    strings:
        $pdf = "%PDF"
        $js = "/JavaScript"
        $open = "/OpenAction"
    condition:
        $pdf at 0 and $js and $open
}

rule Larvanex_PDF_Embedded_File
{
    meta:
        description = "PDF carrying an embedded file attachment"
        severity = "high"
        attack = "T1027.009"
    strings:
        $pdf = "%PDF"
        $embedded = "/EmbeddedFile"
        $launch = "/Launch"
    condition:
        $pdf at 0 and ($embedded or $launch)
}

rule Larvanex_Embedded_PE_In_Document
{
    meta:
        description = "Windows PE header found inside a non-executable file"
        severity = "critical"
        attack = "T1027.009,T1204.002"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz and not $mz at 0 and filesize > 512
}

rule Larvanex_Suspicious_Url_Executable
{
    meta:
        description = "URL pointing directly to an executable payload"
        severity = "medium"
        attack = "T1105"
    strings:
        $url = /https?:\/\/[^\s"'<>]+\.(exe|dll|scr|ps1|vbs|js|hta)/
    condition:
        $url
}

rule Larvanex_Long_Base64_Blob
{
    meta:
        description = "Long base64-looking blob (possible encoded payload)"
        severity = "medium"
        attack = "T1140"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b64
}
