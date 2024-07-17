rule SIGNATURE_BASE_MAL_CRIME_RANSOM_Dearcry_Mar21_1 : FILE
{
	meta:
		description = "Detects DearCry Ransomware affecting Exchange servers"
		author = "Florian Roth (Nextron Systems)"
		id = "96cd2fe8-8bb9-5a3b-9bf1-c63a1148a817"
		date = "2021-03-12"
		modified = "2023-12-05"
		reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_dearcry_ransom.yar#L29-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c4af7c29e917078f8658aca68ec95f8a03934f42c81fdd421639437e24f304bc"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
		hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
		hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"

	strings:
		$s1 = "dear!!!" ascii fullword
		$s2 = "EncryptFile.exe.pdb" ascii fullword
		$s3 = "/readme.txt" ascii fullword
		$s4 = "C:\\Users\\john\\" ascii
		$s5 = "And please send me the following hash!" ascii fullword
		$op1 = { 68 e0 30 52 00 6a 41 68 a5 00 00 00 6a 22 e8 81 d0 f8 ff 83 c4 14 33 c0 5e }
		$op2 = { 68 78 6a 50 00 6a 65 6a 74 6a 10 e8 d9 20 fd ff 83 c4 14 33 c0 5e }
		$op3 = { 31 40 00 13 31 40 00 a4 31 40 00 41 32 40 00 5f 33 40 00 e5 }

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and 3 of them or 5 of them
}