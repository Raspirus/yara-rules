rule TRELLIX_ARC_Ransom_Win_Blackcat : RANSOMWARE FILE
{
	meta:
		description = "Detecting variants of Windows BlackCat malware"
		author = " Trellix ATR"
		id = "65483ffb-6b10-5fd5-8a5f-fc885a5f2e98"
		date = "2022-01-06"
		modified = "2022-01-19"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/Ransom_Win_BlackCat_public.yar#L2-L24"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "8faad28ab26690221f6e2130c886446615dbd505f76490cfaf999d130d0de6e3"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		malware_type = "Ransomware"
		detection_name = "Ransom_Win_BlackCat"
		actor_group = "Unknown"

	strings:
		$URL1 = "zujgzbu5y64xbmvc42addp4lxkoosb4tslf5mehnh7pvqjpwxn5gokyd.onion" ascii wide
		$URL2 = "mu75ltv3lxd24dbyu6gtvmnwybecigs5auki7fces437xvvflzva2nqd.onion" ascii wide
		$API = { 3a 7c d8 3f }

	condition:
		uint16(0)==0x5a4d and filesize <3500KB and 1 of ($URL*) and $API
}