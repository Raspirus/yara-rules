rule EMBEERESEARCH_Win_Redline_Bytecodes_Jan_2024 : FILE
{
	meta:
		description = "Bytecodes found in late 2023 Redline malware"
		author = "Matthew @ Embee_Research"
		id = "8acf0fbb-f7d1-5a3d-9ccb-ee21926d6a31"
		date = "2023-08-27"
		modified = "2024-01-02"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_redline_bytecodes_jan_2024.yar#L1-L22"
		license_url = "N/A"
		hash = "ea1271c032046d482ed94c6d2c2c6e3ede9bea57dff13156cabca42b24fb9332"
		logic_hash = "43f4d718611c16983071587c2806f92550ebba6bae737c59c63cd8584a5cc01f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = {00 00 7E ?? ?? ?? 04 7E ?? ?? ?? 04 28 ?? ?? ?? 06 17 8D ?? ?? ?? 01 25 16 1F 7C 9D 6F ?? ?? ?? 0A 13 ?? 16 13 ?? 38 }
		$s2 = "mscoree.dll" ascii

	condition:
		$s1 and $s2 and uint16(0)==0x5a4d
}