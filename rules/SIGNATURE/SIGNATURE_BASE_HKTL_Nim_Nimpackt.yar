
rule SIGNATURE_BASE_HKTL_Nim_Nimpackt : EXE FILE HKTL
{
	meta:
		description = "Detects binaries generated with NimPackt v1"
		author = "Cas van Cooten"
		id = "3399d937-133f-5701-840e-eaf68b2f1ec9"
		date = "2022-01-26"
		modified = "2023-12-05"
		reference = "https://github.com/chvancooten/NimPackt-v1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_nimpackt.yar#L2-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2bda7acb440d1c72efeaddcb18b736343d658d59feccf6c9339b313cd35f32eb"
		score = 80
		quality = 79
		tags = "EXE, FILE, HKTL"

	strings:
		$nim1 = "fatal.nim" ascii fullword
		$nim2 = "winim" ascii
		$np1 = { 4E 69 6D 50 61 63 6B 74 }
		$sus1 = { 61 6D 73 69 00 00 00 00 B8 57 00 07 80 C3 }
		$sus2 = { 5B 2B 5D 20 49 6E 6A 65 63 74 65 64 }
		$sus3 = { 5C 2D 2D 20 62 79 74 65 73 20 77 72 69 74 74 65 6E 3A }

	condition:
		uint16(0)==0x5A4D and filesize <750KB and 1 of ($nim*) and ($np1 or 2 of ($sus*))
}