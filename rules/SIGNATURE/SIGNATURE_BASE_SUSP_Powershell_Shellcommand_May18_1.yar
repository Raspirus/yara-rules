rule SIGNATURE_BASE_SUSP_Powershell_Shellcommand_May18_1 : FILE
{
	meta:
		description = "Detects a supcicious powershell commandline"
		author = "Tobias Michalski"
		id = "efa81fd0-b764-5a1a-98a5-fc3135be220b"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4369-L4382"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bc858d74b8aad09ff539489e961e1a51ba5fe17d3424615ffe5029587ddb9478"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"

	strings:
		$x1 = "powershell -nop -ep bypass -Command" ascii

	condition:
		filesize <3KB and 1 of them
}