rule SIGNATURE_BASE_MAL_CRIME_Unknown_LNK_Jun21_1 : LNK POWERSHELL FILE
{
	meta:
		description = "Triggers on malicious link files which calls powershell with an obfuscated payload and downloads an HTA file."
		author = "Nils Kuhnert"
		id = "d1aac420-fd91-5577-8efd-fcdd7f733981"
		date = "2021-06-04"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_crime_unknown.yar#L18-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "460e764cbd9fbfa1a2156059d0042a0bea5a939d501050a733a789d236015d37"
		score = 75
		quality = 85
		tags = "LNK, POWERSHELL, FILE"
		hash1 = "8fc7f25da954adcb8f91d5b0e1967e4a90ca132b280aa6ae73e150b55d301942"
		hash2 = "f5da192f4e4dfb6b728aee1821d10bec6d68fb21266ce32b688e8cae7898a522"
		hash3 = "183a9b3c04d16a1822c788d7a6e78943790ee2cdeea12a38e540281091316e45"
		hash4 = "a38c6aa3e1c429a27226519b38f39f03b0b1b9d75fd43cd7e067c5e542967afe"
		hash5 = "455f7b6b975fb8f7afc6295ec40dae5696f5063d1651f3b2477f10976a3b67b2"

	strings:
		$uid = "S-1-5-21-1437133880-1006698037-385855442-1004" wide

	condition:
		uint16(0)==0x004c and all of them
}