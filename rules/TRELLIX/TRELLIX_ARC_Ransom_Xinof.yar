include "TRELLIX_ARC_Ransom_Xinof_Chunk_PRIVATE.yar"

rule TRELLIX_ARC_Ransom_Xinof : RANSOMWARE FILE
{
	meta:
		description = "Detect Xinof ransomware"
		author = "Thomas Roccia | McAfee ATR team"
		id = "3b064ce4-cd5b-5a4a-bb55-a2c2c361791e"
		date = "2020-11-20"
		modified = "2020-11-20"
		reference = "https://labs.sentinelone.com/the-fonix-raas-new-low-key-threat-with-unnecessary-complexities/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_xinof.yar#L53-L82"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "0c1e6299a2392239dbe7fead33ef4146"
		logic_hash = "42110ee8869d56c53dc201cbc83652c6457541b8d502aa12b37ef6200e735a15"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom/XINOF"
		actor_type = "Cybercrime"
		actor_group = "FONIX"

	strings:
		$s1 = "XINOF.exe" nocase ascii
		$s2 = "C:\\Users\\Phoenix" nocase ascii
		$s3 = "How To Decrypt Files.hta" nocase ascii
		$s4 = "C:\\ProgramData\\norunanyway" nocase ascii
		$s5 = "C:\\ProgramData\\clast" nocase ascii
		$s6 = "fonix1" nocase ascii
		$s7 = "C:\\Windows\\System32\\shatdown.exe" nocase ascii
		$s8 = "XINOF Ransomw" nocase ascii
		$s9 = "XINOF v4.2" nocase ascii
		$s10 = "XINOF Ransomware Version 3.3" nocase ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 5 of ($s*) or TRELLIX_ARC_Ransom_Xinof_Chunk_PRIVATE
}