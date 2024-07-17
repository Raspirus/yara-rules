
rule TRELLIX_ARC_Anatova_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect the Anatova Ransomware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "6e3205aa-42e4-5449-877e-37494cdd096b"
		date = "2019-01-22"
		modified = "2020-08-14"
		reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/happy-new-year-2019-anatova-is-here/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Anatova.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "97fb79ca6fc5d24384bf5ae3d01bf5e77f1d2c0716968681e79c097a7d95fb93"
		logic_hash = "4fce15ad0ef2d3cb39f6092677f117308f847815cb2a5a491290a1f9d09776df"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Anatova"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$regex = /anatova[0-9]@tutanota.com/

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and $regex
}