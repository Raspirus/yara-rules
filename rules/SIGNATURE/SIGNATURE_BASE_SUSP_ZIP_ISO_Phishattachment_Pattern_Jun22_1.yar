rule SIGNATURE_BASE_SUSP_ZIP_ISO_Phishattachment_Pattern_Jun22_1 : FILE
{
	meta:
		description = "Detects suspicious small base64 encoded ZIP files (MIME email attachments) with .iso files as content as often used in phishing attacks"
		author = "Florian Roth (Nextron Systems)"
		id = "638541a6-d2d4-513e-978c-9d1b9f5e3b71"
		date = "2022-06-23"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_phish_attachments.yar#L23-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "21de56d6209050b429c0cce82fd334d1b38a2a3727db5ead06f36fa9d503e193"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$pkzip_base64_1 = { 0A 55 45 73 44 42 }
		$pkzip_base64_2 = { 0A 55 45 73 44 42 }
		$pkzip_base64_3 = { 0A 55 45 73 48 43 }
		$iso_1 = "Lmlzb1BL"
		$iso_2 = "5pc29QS"
		$iso_3 = "uaXNvUE"

	condition:
		filesize <2000KB and 1 of ($pk*) and 1 of ($iso*)
}