
rule SIGNATURE_BASE_Sleep_Timer_Choice : FILE
{
	meta:
		description = "Detects malware from NCSC report"
		author = "NCSC"
		id = "c64db0dd-2858-5508-ac51-d3318113a060"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ncsc_report_04_2018.yar#L39-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		logic_hash = "5d2b656aabb113c50805d4af0faa62f579547dd4ec328ff2778fab64d778b8b9"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = {8b0424b90f00000083f9ff743499f7f98d420f}

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of ($a*)
}