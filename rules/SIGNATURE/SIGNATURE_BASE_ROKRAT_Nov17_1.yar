rule SIGNATURE_BASE_ROKRAT_Nov17_1 : FILE
{
	meta:
		description = "Detects ROKRAT malware"
		author = "Florian Roth (Nextron Systems)"
		id = "6bf3653b-1f96-5060-b6fd-82ccc83fad77"
		date = "2017-11-28"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_rokrat.yar#L110-L127"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "12641d417408ef32292204f620efa3d1347238fa1c6f63b2b6f09a6c660e9e24"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\T+M\\Result\\DocPrint.pdb" ascii
		$s2 = "d:\\HighSchool\\version 13\\2ndBD" ascii
		$s3 = "e:\\Happy\\Work\\Source\\version" ascii
		$x1 = "\\appdata\\local\\svchost.exe" ascii
		$x2 = "c:\\temp\\esoftscrap.jpg" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and 1 of them )
}