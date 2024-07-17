
rule ELCEEF_Suspicious_SFX : FILE
{
	meta:
		description = "Detects self-extracting archives (SFX) executing cmd.exe or powershell.exe"
		author = "marcin@ulikowski.pl"
		id = "78f4ae8b-ba17-5c02-a6f0-66bec873aba8"
		date = "2023-04-04"
		modified = "2023-04-04"
		reference = "https://www.crowdstrike.com/blog/self-extracting-archives-decoy-files-and-their-hidden-payloads/"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/Suspicious_SFX.yara#L1-L22"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "688ed356e2fa936a0e07a8479591c28fb457053ed94351bad4bf367b02f04b0a"
		score = 65
		quality = 73
		tags = "FILE"

	strings:
		$rar = { 52 61 72 21 }
		$zip = { 50 4b 03 04 }
		$setup_cmd = "\nSetup=cmd"
		$setup_powershell = "\nSetup=powershell"
		$silent = "\nSilent=1"

	condition:
		filesize <1MB and uint16be(0)==0x4d5a and any of ($zip,$rar) and any of ($setup_*) and $silent
}