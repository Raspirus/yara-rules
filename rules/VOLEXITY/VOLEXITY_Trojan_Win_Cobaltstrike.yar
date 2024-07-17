import "pe"


rule VOLEXITY_Trojan_Win_Cobaltstrike : COMMODITY
{
	meta:
		description = "The CobaltStrike malware family."
		author = "threatintel@volexity.com"
		id = "113ba304-261f-5c59-bc56-57515c239b6d"
		date = "2021-05-25"
		modified = "2021-09-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L21-L41"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
		logic_hash = "1e8a68050ff25f77e903af2e0a85579be1af77c64684e42e8f357eee4ae59377"
		score = 75
		quality = 80
		tags = "COMMODITY"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "%s (admin)" fullword
		$s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
		$s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
		$s4 = "%s as %s\\%s: %d" fullword
		$s5 = "%s&%s=%s" fullword
		$s6 = "rijndael" fullword
		$s7 = "(null)"

	condition:
		all of them
}