rule TRELLIX_ARC_Nefilim_Signed : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect Nefilim samples digitally signed"
		author = "Marc Rivero | McAfee ATR Team"
		id = "a9a5daf0-4cfb-556a-b20a-72283fb1a0f9"
		date = "2020-04-02"
		modified = "2020-08-14"
		reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_NEFILIM.yar#L50-L72"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "353ee5805bc5c7a98fb5d522b15743055484dc47144535628d102a4098532cd5"
		logic_hash = "7625eb7de1ebb2f5410552b8983379f213d639f5e146a5d951975b69eb8111d3"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Nefilim"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Red GmbH/CN=Red GmbH" and pe.signatures[i].serial=="00:b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a" or pe.signatures[i].thumbprint=="5b:19:58:8b:78:74:0a:4c:5d:08:41:99:dc:0f:52:a6:1f:38:00:99")
}