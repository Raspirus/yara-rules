rule SIGNATURE_BASE_MAL_DOC_Zloader_Oct20_1 : FILE
{
	meta:
		description = "Detects weaponized ZLoader documents"
		author = "Florian Roth (Nextron Systems)"
		id = "34145746-9733-5dd9-9dcf-99e3a3ceee4f"
		date = "2020-10-10"
		modified = "2023-12-05"
		reference = "https://twitter.com/JohnLaTwC/status/1314602421977452544"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_zloader_maldocs.yar#L2-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6f546a860361d3caff99c282465dbbd1880460c7491a1b5ad065c1b5d91e5d49"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "668ca7ede54664360b0a44d5e19e76beb92c19659a8dec0e7085d05528df42b5"
		hash2 = "a2ffabbb1b5a124f462a51fee41221081345ec084d768ffe1b1ef72d555eb0a0"
		hash3 = "d268af19db475893a3d19f76be30bb063ab2ca188d1b5a70e51d260105b201da"

	strings:
		$sc1 = { 78 4E FC 04 AB 6B 17 E2 33 E3 49 62 50 69 BB 60
               31 00 1E 00 02 4B BA E2 D8 E3 92 22 1E 69 96 20
               98 }
		$sc2 = { 6B 9E E2 36 E3 69 62 72 69 3A 60 55 6E }
		$sc3 = { 3E 69 76 60 59 6E 34 FB 87 6B 75 }

	condition:
		uint16(0)==0xcfd0 and filesize <40KB and filesize >30KB and all of them
}