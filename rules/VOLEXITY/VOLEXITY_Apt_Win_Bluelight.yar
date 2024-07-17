rule VOLEXITY_Apt_Win_Bluelight : INKYSQUID
{
	meta:
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
		author = "threatintel@volexity.com"
		id = "3ec2d44c-4c08-514d-a839-acef3f53f7dc"
		date = "2021-04-23"
		modified = "2021-09-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-08-17 - InkySquid Part 1/indicators/yara.yar#L102-L132"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "52589348f42aadbe453ad8a40ac36b58fcc9e07cd298486f09b6f793823d8cc7"
		score = 75
		quality = 80
		tags = "INKYSQUID"
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$pdb1 = "\\Development\\BACKDOOR\\ncov\\"
		$pdb2 = "Release\\bluelight.pdb"
		$msg0 = "https://ipinfo.io" fullword
		$msg1 = "country" fullword
		$msg5 = "\"UserName\":\"" fullword
		$msg7 = "\"ComName\":\"" fullword
		$msg8 = "\"OS\":\"" fullword
		$msg9 = "\"OnlineIP\":\"" fullword
		$msg10 = "\"LocalIP\":\"" fullword
		$msg11 = "\"Time\":\"" fullword
		$msg12 = "\"Compiled\":\"" fullword
		$msg13 = "\"Process Level\":\"" fullword
		$msg14 = "\"AntiVirus\":\"" fullword
		$msg15 = "\"VM\":\"" fullword

	condition:
		any of ($pdb*) or all of ($msg*)
}