
rule SIGNATURE_BASE_Partial_Implant_ID : FILE
{
	meta:
		description = "Detects implant from NCSC report"
		author = "NCSC"
		id = "15144f4a-2c96-57f0-b7e9-adbac477c38a"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ncsc_report_04_2018.yar#L24-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		logic_hash = "d0a29bed3c19007cb08427769918b0a02d5d247211a1ceaff31aed5839c78966"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$a1 = {38 38 31 34 35 36 46 43}

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of ($a*)
}