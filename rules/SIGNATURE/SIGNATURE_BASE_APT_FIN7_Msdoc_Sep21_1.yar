rule SIGNATURE_BASE_APT_FIN7_Msdoc_Sep21_1 : FILE
{
	meta:
		description = "Detects MalDocs used by FIN7 group"
		author = "Florian Roth (Nextron Systems)"
		id = "4fbde087-ec1e-5614-af1e-f342b1766fa2"
		date = "2021-09-07"
		modified = "2023-12-05"
		reference = "https://www.anomali.com/blog/cybercrime-group-fin7-using-windows-11-alpha-themed-docs-to-drop-javascript-backdoor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L277-L301"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ffc91cdad91b8ab24840c6ef1a6c39aad081d986c21a88b3f2ea3ec1bcd3b52b"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "d60b6a8310373c9b84e6760c24185535"

	strings:
		$xc1 = { 00 4A 00 6F 00 68 00 6E 00 0B 00 57 00 31 00 30
               00 50 00 72 00 6F 00 4F 00 66 00 66 00 31 00 36 }
		$s1 = "word_data.bin" ascii fullword
		$s2 = "V:\\DOC\\For_JS" ascii
		$s3 = "HomeCompany" ascii
		$s4 = "W10ProOff16" ascii

	condition:
		uint16(0)==0xcfd0 and (1 of ($x*) or 3 of them )
}