import "pe"


import "pe"


rule SIGNATURE_BASE_MAL_Exilerat_Feb19_1 : FILE
{
	meta:
		description = "Detects Exile RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "f0a510f3-5fea-59a7-8991-9d06dc478b2a"
		date = "2019-02-04"
		modified = "2023-12-05"
		reference = "https://creativecommons.org/licenses/by-nc/4.0/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_exile_rat.yar#L4-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0556bc0dbd33502d5bf823cf265a4e133d9af43076abe35a86cf5e20ab314e35"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3eb026d8b778716231a07b3dbbdc99e2d3a635b1956de8a1e6efc659330e52de"

	strings:
		$x1 = "Content-Disposition:form-data;name=\"x.bin\"" fullword ascii
		$s1 = "syshost.dll" fullword ascii
		$s2 = "\\scout\\Release\\scout.pdb" ascii
		$s3 = "C:\\data.ini" fullword ascii
		$s4 = "my-ip\" value=\"" fullword ascii
		$s5 = "ver:%d.%d.%d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="da8475fc7c3c90c0604ce6a0b56b5f21" or 3 of them )
}