rule SIGNATURE_BASE_HKTL_Bruteratel_Badger_Indicators_Oct22_4 : FILE
{
	meta:
		description = "Detects Brute Ratel C4 badger indicators"
		author = "Matthew @embee_research, Florian Roth"
		id = "a62d08ae-0fb3-55e9-b6f8-7940f8032e4a"
		date = "2022-10-12"
		modified = "2023-12-05"
		reference = "https://twitter.com/embee_research/status/1580030310778953728"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/hktl_bruteratel_c4_badger.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9af05225f462c8d4ec1fb14dc06bb789f76b0d818cb82c3dfcd5abc693727f33"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = { b? 89 4d 39 8c }
		$s2 = { b? bd ca 3b d3 }
		$s3 = { b? b2 c1 06 ae }
		$s4 = { b? 74 eb 1d 4d }

	condition:
		filesize <8000KB and all of ($s*) and not uint8(0)==0x02
}