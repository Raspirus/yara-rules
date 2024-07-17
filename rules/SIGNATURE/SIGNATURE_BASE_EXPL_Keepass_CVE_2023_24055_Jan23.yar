
rule SIGNATURE_BASE_EXPL_Keepass_CVE_2023_24055_Jan23 : CVE_2023_24055 FILE
{
	meta:
		description = "Detects suspicious entries in the Keepass configuration file, which could be indicator of the exploitation of CVE-2023-24055"
		author = "Florian Roth (Nextron Systems)"
		id = "2c031919-da19-5fd0-b21a-2e83679ad1e3"
		date = "2023-01-25"
		modified = "2023-12-05"
		reference = "https://github.com/alt3kx/CVE-2023-24055_PoC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_keepass_cve_2023_24055.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3ca00f317838819bb7fb80c9d00d94db498e1d3ef146b9af2664dae09302a86d"
		score = 75
		quality = 81
		tags = "CVE-2023-24055, FILE"

	strings:
		$a1 = "<TriggerCollection xmlns:xsi=" ascii wide
		$x1 = "<Parameter>KeePass XML (2.x)</Parameter>"
		$x2 = "::ReadAllBytes("
		$x3 = " -Method "
		$x4 = " bypass "
		$x5 = "powershell" nocase ascii wide fullword

	condition:
		filesize <200KB and $a1 and 1 of ($x*)
}