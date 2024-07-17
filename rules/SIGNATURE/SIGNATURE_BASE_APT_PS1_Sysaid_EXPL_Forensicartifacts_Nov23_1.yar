rule SIGNATURE_BASE_APT_PS1_Sysaid_EXPL_Forensicartifacts_Nov23_1 : SCRIPT CVE_2023_47246
{
	meta:
		description = "Detects forensic artifacts found in attacks on SysAid on-prem software exploiting CVE-2023-47246"
		author = "Florian Roth"
		id = "df7997d3-9309-58b3-8cd7-de9fea36d3c7"
		date = "2023-11-09"
		modified = "2023-12-05"
		reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_sysaid_cve_2023_47246.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "85efeea88961ca99b22004726d88efc46c748273b9a0b3be674f4cbb12cd3dd1"
		score = 85
		quality = 85
		tags = "SCRIPT, CVE-2023-47246"

	strings:
		$x1 = "if ($s -match '^(Sophos).*\\.exe\\s') {echo $s; $bp++;}" ascii wide
		$x2 = "$s=$env:SehCore;$env:SehCore=\"\";Invoke-Expression $s;" ascii wide

	condition:
		1 of them
}