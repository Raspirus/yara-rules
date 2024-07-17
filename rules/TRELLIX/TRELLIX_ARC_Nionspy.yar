
rule TRELLIX_ARC_Nionspy : FILEINFECTOR FILE
{
	meta:
		description = "Triggers on old and new variants of W32/NionSpy file infector"
		author = "Trellix ARC Team"
		id = "86051ef8-a18b-553c-b06c-490f8d6df5cf"
		date = "2024-06-01"
		modified = "2020-08-14"
		reference = "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_NionSpy.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "982ba52f39352aee9e2d2dcadfb0816c439e92d0e5947afa7860630720913742"
		score = 75
		quality = 70
		tags = "FILEINFECTOR, FILE"
		malware_type = "fileinfector"
		malware_family = "FileInfector:W32/NionSpy"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$variant2015_infmarker = "aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT"
		$variant2013_infmarker = "ad6af8bd5835d19cc7fdc4c62fdf02a1"
		$variant2013_string = "%s?cstorage=shell&comp=%s"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and 1 of ($variant*)
}