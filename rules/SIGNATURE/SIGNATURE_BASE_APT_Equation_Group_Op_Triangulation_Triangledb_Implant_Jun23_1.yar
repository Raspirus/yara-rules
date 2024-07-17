import "pe"


import "pe"


import "pe"


rule SIGNATURE_BASE_APT_Equation_Group_Op_Triangulation_Triangledb_Implant_Jun23_1 : FILE
{
	meta:
		description = "Detects TriangleDB implant found being used in Operation Triangulation on iOS devices (maybe also used on macOS systems)"
		author = "Florian Roth"
		id = "d81a5103-41c8-5dba-a560-8fb5514f6c0a"
		date = "2023-06-21"
		modified = "2023-12-05"
		reference = "https://securelist.com/triangledb-triangulation-implant/110050/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_triangulation_jun23.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "486b19ddb8b182dbba882359f7eb416735e76f9cda5aea1b290fb5c6b44960c5"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "unmungeHexString" ascii fullword
		$s2 = "CRPwrInfo" ascii fullword
		$s3 = "CRConfig" ascii fullword
		$s4 = "CRXConfigureDBServer" ascii fullword

	condition:
		( uint16(0)==0xfacf and filesize <30MB and $s1 and 2 of them ) or all of them
}