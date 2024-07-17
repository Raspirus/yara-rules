rule SIGNATURE_BASE_Lnk_Detect : FILE
{
	meta:
		description = "Detects malicious LNK file from NCSC report"
		author = "NCSC"
		id = "76d382f3-b2f2-5ede-94b2-5ae8b766c194"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ncsc_report_04_2018.yar#L126-L149"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ae8796877d70f8ddd56bac8ed474231f26d9bc8e73625e65d5d927ab804996b3"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$lnk_magic = {4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46}
		$lnk_target = {41 00 55 00 54 00 4F 00 45 00 58 00 45 00 43 00 2E 00 42 00 41 00 54}
		$s1 = {5C 00 5C 00 31 00}
		$s2 = {5C 00 5C 00 32 00}
		$s3 = {5C 00 5C 00 33 00}
		$s4 = {5C 00 5C 00 34 00}
		$s5 = {5C 00 5C 00 35 00}
		$s6 = {5C 00 5C 00 36 00}
		$s7 = {5C 00 5C 00 37 00}
		$s8 = {5C 00 5C 00 38 00}
		$s9 = {5C 00 5C 00 39 00}

	condition:
		uint32be(0)==0x4c000000 and uint32be(4)==0x01140200 and (($lnk_magic at 0) and $lnk_target) and 1 of ($s*)
}