rule SIGNATURE_BASE_SUSP_LNK_Embedded_Worddoc : FILE
{
	meta:
		description = "check for LNK files with indications of the Word program or an embedded doc"
		author = "Greg Lesnewich"
		id = "9677d41a-9d29-510c-98cd-122dc0ca9606"
		date = "2023-01-02"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_100days_of_yara_2023.yar#L3-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		logic_hash = "a53fbfe0ccb5a4ab2320cde10d17f29770d888cf21cda4fdccc3d7ae8d123293"
		score = 65
		quality = 85
		tags = "FILE"
		version = "1.0"
		DaysofYARA = "2/100"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$icon_loc = "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.exe" ascii wide

	condition:
		uint32be(0x0)==0x4C000000 and filesize >10KB and any of them
}