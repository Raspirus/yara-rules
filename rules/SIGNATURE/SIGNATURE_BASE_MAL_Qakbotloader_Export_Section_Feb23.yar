rule SIGNATURE_BASE_MAL_Qakbotloader_Export_Section_Feb23 : FILE
{
	meta:
		description = "QakBot Export Selection"
		author = "kevoreilly"
		id = "cb86e9fb-a8d2-5285-aeda-622704399f8e"
		date = "2023-02-17"
		modified = "2023-12-05"
		reference = "https://github.com/kevoreilly/CAPEv2/blob/master/LICENSE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_qbot_feb23.yar#L22-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "6f99171c95a8ed5d056eeb9234dbbee123a6f95f481ad0e0a966abd2844f0e1a"
		logic_hash = "0e40cd6acdbfb17670b414bd6f2ecdf1ae26ddd6a5d85931973b98963a43aba8"
		score = 75
		quality = 85
		tags = "FILE"
		cape_options = "export=$export"

	strings:
		$export = {55 8B EC 83 EC 50 (3A|66 3B) ?? 74}
		$wind = {(66 3B|3A) ?? 74 [1-14] BB 69 04 00 00 53 E8 [5-7] 74}

	condition:
		uint16(0)==0x5A4D and all of them
}