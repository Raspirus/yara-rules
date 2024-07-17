rule SIGNATURE_BASE_WINNTI_Kingsoft_Moz_Confustion : FILE
{
	meta:
		description = "Detects Barium sample with Copyright confusion"
		author = "Markus Neis"
		id = "0c45c1ff-6734-504f-91d1-cf5d6744252f"
		date = "2018-04-13"
		modified = "2023-12-05"
		reference = "https://www.virustotal.com/en/file/070ee4a40852b26ec0cfd79e32176287a6b9d2b15e377281d8414550a83f6496/analysis/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti.yar#L143-L159"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ebd8465f484e1142ac741263282ea1c6f98e6bd0637ebdcec6ecc6233193407e"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "070ee4a40852b26ec0cfd79e32176287a6b9d2b15e377281d8414550a83f6496"

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (pe.imphash()=="7f01b23ccfd1017249c36bc1618d6892" or (pe.version_info["LegalCopyright"] contains "Mozilla Corporation" and pe.version_info["ProductName"] contains "Kingsoft"))
}