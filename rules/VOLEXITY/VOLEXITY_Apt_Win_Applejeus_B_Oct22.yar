rule VOLEXITY_Apt_Win_Applejeus_B_Oct22 : LAZARUS
{
	meta:
		description = "Detected AppleJeus unpacked samples."
		author = "threatintel@volexity.com"
		id = "8586dc64-225b-5f28-a6d6-b9b6e8f1c815"
		date = "2022-11-03"
		modified = "2022-12-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L18-L41"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "76f3c9692ea96d3cadbbcad03477ab6c53445935352cb215152b9b5483666d43"
		score = 75
		quality = 80
		tags = "LAZARUS"
		hash1 = "9352625b3e6a3c998e328e11ad43efb5602fe669aed9c9388af5f55fadfedc78"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$key1 = "AppX7y4nbzq37zn4ks9k7amqjywdat7d"
		$key2 = "Gd2n5frvG2eZ1KOe"
		$str1 = "Windows %d(%d)-%s"
		$str2 = "&act=check"

	condition:
		( any of ($key*) and 1 of ($str*)) or all of ($str*)
}