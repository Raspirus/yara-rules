
rule TRELLIX_ARC_Kraken_Cryptor_Ransomware_Loader : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect the Kraken Cryptor Ransomware loader"
		author = "Marc Rivero | McAfee ATR Team"
		id = "e6bfa30b-6565-5d03-8f4d-96fc2b6a1c11"
		date = "2018-09-30"
		modified = "2020-08-14"
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Kraken.yar#L1-L30"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"
		logic_hash = "9e252a3ba7f6bf861ea7563461a1420959dfb0f5b7c3f6071150d03422504539"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Kraken"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "C:\\Users\\Krypton\\source\\repos\\UAC\\UAC\\obj\\Release\\UAC.pdb" fullword ascii
		$s2 = "SOFTWARE\\Classes\\mscfile\\shell\\open\\command" fullword wide
		$s3 = "public_key" fullword ascii
		$s4 = "KRAKEN DECRYPTOR" ascii
		$s5 = "UNIQUE KEY" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and $pdb or all of ($s*)
}