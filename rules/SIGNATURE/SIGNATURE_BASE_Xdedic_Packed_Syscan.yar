rule SIGNATURE_BASE_Xdedic_Packed_Syscan : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Kaspersky Lab - modified by Florian Roth"
		id = "da8e59f3-53f9-504b-afff-9caab798db6c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sysscan.yar#L29-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "04eb5b056e892b2c2cf87e3770847226cccaceb1c743f3b9f8ac548026747ccf"
		score = 75
		quality = 83
		tags = "FILE"
		company = "Kaspersky Lab"

	strings:
		$a1 = "SysScan.exe" nocase ascii wide
		$a2 = "1.3.4." wide

	condition:
		uint16(0)==0x5A4D and filesize >500KB and filesize <1500KB and all of them
}