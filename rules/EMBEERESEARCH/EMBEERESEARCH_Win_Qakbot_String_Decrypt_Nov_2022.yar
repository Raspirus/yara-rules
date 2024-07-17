rule EMBEERESEARCH_Win_Qakbot_String_Decrypt_Nov_2022 : FILE
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "Embee_Research @ Huntress"
		id = "0023872f-8edb-59d6-88eb-a76528ba6ec8"
		date = "2022-11-14"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/2022/win_qakbot_string_decrypt_nov_2022.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "d225f69fa4dd0e8d7c98e7f8968ad285f05b232225e9ce1070b7a23257a0ef9d"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$qakbot_decrypt = {33 d2 8b c7 f7 75 10 8a 04 1a 8b 55 fc 32 04 17 88 04 39 47 83 ee 01}

	condition:
		uint16(0)==0x5a4d and $qakbot_decrypt
}