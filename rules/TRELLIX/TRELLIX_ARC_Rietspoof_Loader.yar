rule TRELLIX_ARC_Rietspoof_Loader : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect the Rietspoof loader"
		author = "Marc Rivero | McAfee ATR Team"
		id = "f306e381-e2ae-528e-937b-aced72356d77"
		date = "2024-06-01"
		modified = "2020-08-14"
		reference = "https://blog.avast.com/rietspoof-malware-increases-activity"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_rietspoof_loader.yar#L1-L22"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "d72b58ff452070e03d0b25bc433ef5c677df77dd440adc1ecdb592cee24235fb"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		malware_type = "ransomware"
		malware_family = "Loader:W32/Rietspoof"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$x1 = "\\Work\\d2Od7s43\\techloader\\loader" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}