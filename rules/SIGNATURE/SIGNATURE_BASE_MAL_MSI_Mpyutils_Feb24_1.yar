rule SIGNATURE_BASE_MAL_MSI_Mpyutils_Feb24_1 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects malicious MSI package mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		id = "e7794336-a325-5b92-8c25-81ed9cb28044"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L230-L247"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ba20db486e5d3c29c9702e10628fb3c0e55e52bbec74e3a86ed6511a6475b82f"
		score = 70
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "8e51de4774d27ad31a83d5df060ba008148665ab9caf6bc889a5e3fba4d7e600"

	strings:
		$s1 = "crypt64ult.exe" ascii fullword
		$s2 = "EXPAND.EXE" wide fullword
		$s6 = "ICACLS.EXE" wide fullword

	condition:
		uint16(0)==0xcfd0 and filesize <20000KB and all of them
}