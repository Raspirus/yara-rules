
rule TRELLIX_ARC_Malw_Eicar : EICAR
{
	meta:
		description = "Rule to detect the EICAR pattern"
		author = "Marc Rivero | McAfee ATR Team"
		id = "16307b03-7fab-5d68-ad3b-0efcea952fcf"
		date = "2024-06-01"
		modified = "2020-08-14"
		reference = "https://www.eicar.org/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_Eicar.yar#L1-L22"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
		logic_hash = "564b0592f40582fe71e2dab0c0f25c168462f9297c13e7c9f06ac51b492e4533"
		score = 75
		quality = 70
		tags = "EICAR"
		malware_type = "eicar"
		malware_family = "W32/Eicar"
		actor_type = "Unknown"
		actor_group = "Unknown"

	strings:
		$s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii

	condition:
		any of them
}