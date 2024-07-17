
rule SIGNATURE_BASE_APT_KE3CHANG_TMPFILE : APT KE3CHANG TMPFILE FILE
{
	meta:
		description = "Detects Strings left in TMP Files created by K3CHANG Backdoor Ketrican"
		author = "Markus Neis, Swisscom"
		id = "84d411af-ea3d-5862-8c2f-7caca60c1b66"
		date = "2020-06-18"
		modified = "2023-12-05"
		reference = "https://app.any.run/tasks/a96f4f9d-c27d-490b-b5d3-e3be0a1c93e9/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ke3chang.yar#L1-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "75c97fe2eeb82e09f52e98d76bd529824f171da4c802b5febc1036314d8145f0"
		score = 75
		quality = 85
		tags = "APT, KE3CHANG, TMPFILE, FILE"
		hash1 = "4ef11e84d5203c0c425d1a76d4bf579883d40577c2e781cdccc2cc4c8a8d346f"

	strings:
		$pps1 = "PSParentPath             : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
		$pps2 = "PSPath                   : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
		$psp1 = ": Microsoft.PowerShell.Core\\Registry" ascii
		$s4 = "PSChildName  : PhishingFilter" fullword ascii
		$s1 = "DisableFirstRunCustomize : 2" fullword ascii
		$s7 = "PSChildName  : 3" fullword ascii
		$s8 = "2500         : 3" fullword ascii

	condition:
		uint16(0)==0x5350 and filesize <1KB and $psp1 and 1 of ($pps*) and 1 of ($s*)
}