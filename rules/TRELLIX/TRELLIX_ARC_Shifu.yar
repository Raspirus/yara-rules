
rule TRELLIX_ARC_Shifu : FINANCIAL
{
	meta:
		description = "No description has been set in the source file - Trellix ARC"
		author = "McAfee Labs"
		id = "81e9ad25-1df0-5196-be8b-1d1d5d8e4387"
		date = "2024-06-01"
		modified = "2020-08-14"
		reference = "https://blogs.mcafee.com/mcafee-labs/japanese-banking-trojan-shifu-combines-malware-tools/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_Shifu.yar#L1-L24"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "dfa6165f8d2750330c71dedbde293780d2bb27e8eb3635e47ca770ff7b9a9d63"
		score = 75
		quality = 70
		tags = "FINANCIAL"
		malware_type = "financial"
		malware_family = "Backdoor:W32/Shifu"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$b = "RegCreateKeyA"
		$a = "CryptCreateHash"
		$c = {2F 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 25 00 73 00 00 00 00 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 00 00 72 00 75 00 6E}
		$d = {53 00 6E 00 64 00 56 00 6F 00 6C 00 2E 00 65 00 78 00 65}
		$e = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45}

	condition:
		all of them
}