import "pe"


rule TRELLIX_ARC_Ransom_Conti : RANSOMWARE FILE
{
	meta:
		description = "Conti ransomware is havnig capability too scan and encrypt oover the network"
		author = "McAfee ATR team"
		id = "8fc6943d-fb99-5957-929b-4c264d9fba2d"
		date = "2020-07-09"
		modified = "2020-10-12"
		reference = "https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/Ransom_Conti.yar#L3-L37"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe"
		logic_hash = "953471c130309bbc712197d49d2072bd45838f49d2b25f86273a15c6baa87354"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Conti"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$string1 = "HOW_TO_DECRYPTP" fullword ascii
		$string2 = "The system is LOCKED." fullword ascii
		$string3 = "The network is LOCKED." fullword ascii
		$code1 = { ff b4 b5 48 ff ff ff 53 ff 15 bc b0 41 00 85 c0 }
		$code2 = { 6a 02 6a 00 6a ff 68 ec fd ff ff ff 76 0c ff 15 }
		$code3 = { 56 8d 85 38 ff ff ff 50 ff d7 85 c0 0f 84 f2 01 }

	condition:
		uint16(0)==0x5a4d and filesize <300KB and pe.number_of_sections==5 and (pe.imphash()=="30fe3f044289487cddc09bfb16ee1fde" or ( all of them and all of ($code*)))
}