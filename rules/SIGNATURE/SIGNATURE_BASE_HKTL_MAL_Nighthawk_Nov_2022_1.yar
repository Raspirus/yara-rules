rule SIGNATURE_BASE_HKTL_MAL_Nighthawk_Nov_2022_1 : NIGHTHAWK BEACON FILE
{
	meta:
		description = "Detect the Nighthawk dropped beacon"
		author = "Arkbird_SOLG"
		id = "a46d5034-e8e3-5c30-90d9-ea97b8384341"
		date = "2022-11-22"
		modified = "2023-12-05"
		reference = "https://web.archive.org/web/20221125224850/https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_nighthawk_c2.yar#L32-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8dec7752ee6e1af87129ce7ac09130f94a20807c4f45ceb1fce434358ac727bf"
		score = 75
		quality = 85
		tags = "NIGHTHAWK, BEACON, FILE"
		hash1 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"
		hash2 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
		hash3 = "f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e"

	strings:
		$s1 = { 44 8b ff 45 33 c0 48 8d 15 [2] 0a 00 48 8d 4d c0 e8 [2] ff ff 45 33 c0 48 8d 15 [2] 0a 00 48 8d 4d 20 e8 [2] ff ff 45 33 c0 48 8d 15 [2] 0a 00 48 8d 4d 00 e8 [2] ff ff 45 33 c0 48 8d 15 [2] 0a 00 48 8d 4d e0 e8 [2] ff ff 33 d2 e9 ee 04 00 00 48 8d 44 24 68 48 89 44 24 20 41 b9 01 00 00 00 45 33 c0 48 8d 95 a0 00 00 00 ff 15 [2] 09 00 85 c0 0f 85 74 04 00 00 48 89 7c 24 28 48 89 7c 24 20 45 33 c9 45 33 c0 48 8d 15 [2] 0a 00 48 8b 4c 24 68 ff 15 [2] 09 00 85 }
		$s2 = { 4d 85 c0 0f 84 83 00 00 00 49 21 18 33 d2 44 8d 43 01 33 c9 ff 15 [2] 08 00 48 8b f0 48 85 c0 74 6a 44 8d 43 04 48 8b d5 48 8b c8 ff 15 [2] 08 00 48 8b e8 48 85 c0 74 49 48 8d 44 24 70 33 d2 44 8d 4b 24 48 89 44 24 20 4c 8d 44 24 30 48 8b cd ff 15 [2] 08 00 8b }
		$s3 = { 48 85 c0 0f 84 [2] 00 00 4d 8b cc 49 83 7c 24 18 08 72 04 4d 8b 0c 24 4d 8b c5 49 83 7d 18 08 72 04 4d 8b 45 00 49 8b ?? 49 83 ?? 18 08 72 03 49 8b }
		$s4 = { 44 8b 44 24 44 4c 89 [2-3] 89 95 00 02 00 00 2b c7 8b d7 49 03 d0 48 03 d1 4c 8d 8d 00 02 00 00 44 8b c0 49 8b cf ff 15 [2] 04 00 33 d2 85 c0 0f 84 [2] ff ff 03 bd 00 02 00 00 8b 44 24 40 3b f8 48 8b 4d ?? 4c 8b }

	condition:
		uint16(0)==0x5A4D and filesize >60KB and all of ($s*)
}