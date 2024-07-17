rule VOLEXITY_Apt_Win_Applejeus_C_Oct22 : LAZARUS
{
	meta:
		description = "Detected AppleJeus unpacked samples."
		author = "threatintel@volexity.com"
		id = "6f467e0e-2932-5ba7-9fe3-0f9d28466e23"
		date = "2022-11-03"
		modified = "2022-12-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L43-L63"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "566f5840ff2023f4fd8ffaa9ba1308a7012913cf587838173358b8f1fe4abca8"
		score = 75
		quality = 80
		tags = "LAZARUS"
		hash1 = "a0db8f8f13a27df1eacbc01505f311f6b14cf9b84fbc7e84cb764a13f001dbbb"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$str1 = "%sd.e%sc \"%s > %s 2>&1\"" wide
		$str2 = "tuid"
		$str3 = "content"
		$str4 = "payload"
		$str5 = "fconn"
		$str6 = "Mozilla_%lu"

	condition:
		5 of them
}