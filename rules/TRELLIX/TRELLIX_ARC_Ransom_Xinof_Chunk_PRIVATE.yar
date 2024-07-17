rule TRELLIX_ARC_Ransom_Xinof_Chunk_PRIVATE : RANSOMWARE
{
	meta:
		description = "Detect chunk of Xinof ransomware"
		author = "Thomas Roccia | McAfee ATR Team"
		id = "243c39fd-b5f6-5f64-8058-43da182480c0"
		date = "2020-11-20"
		date = "2020-11-20"
		modified = "2020-11-20"
		reference = "https://labs.sentinelone.com/the-fonix-raas-new-low-key-threat-with-unnecessary-complexities/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_xinof.yar#L1-L51"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "0c1e6299a2392239dbe7fead33ef4146"
		logic_hash = "f0266962357a7cb26995cdbfcc99749b73fc4ed09c813fa8e2ed0f5143cde554"
		score = 75
		quality = 70
		tags = "RANSOMWARE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom/XINOF"
		actor_type = "Cybercrime"
		actor_group = "FONIX"

	strings:
		$chunk1 = {
		   C6 45 ?? ??
		   68 ?? ?? ?? ??
	           50
		   E8 ?? ?? ?? ??
		   53
	           50
		   8D 85 ?? ?? ?? ??
		   C6 45 ?? ??
		   50
		   E8 ?? ?? ?? ??
		   56
		   50
		   8D 85 ?? ?? ?? ??
		   C6 45 ?? ??
		   50
		   E8 ?? ?? ?? ??
		   83 C4 ??
		   C6 45 ?? ??
		   8B CC
		   57
		   50
		   51
		   E8 ?? ?? ?? ??
		   83 C4 ??
		   8D 8D ?? ?? ?? ??
		   E8 ?? ?? ?? ??
		   83 C4 ??
		   8D 8D ?? ?? ?? ??
		   E8 ?? ?? ?? ??
		}

	condition:
		any of them
}