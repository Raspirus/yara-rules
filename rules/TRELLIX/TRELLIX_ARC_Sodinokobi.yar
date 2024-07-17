rule TRELLIX_ARC_Sodinokobi : RANSOMWARE
{
	meta:
		description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
		author = "McAfee ATR team"
		id = "dd05ce31-9699-50a9-944c-5883340791af"
		date = "2024-06-01"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Sodinokibi.yar#L33-L54"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "f25039ac743223756461bbeeb349c674473608f9959bf3c79ce4a7587fde3ab2"
		score = 75
		quality = 70
		tags = "RANSOMWARE"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Sodinokibi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		version = "1.0"

	strings:
		$a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
		$b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

	condition:
		all of them
}