rule SIGNATURE_BASE_MAL_Dropper_Win_Darkside_1 : FILE
{
	meta:
		description = "Detection for on the binary that was used as the dropper leading to DARKSIDE."
		author = "FireEye"
		id = "910a581c-25a4-5d5e-acdc-6d87cbedd3cf"
		date = "2021-05-11"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_ransom_darkside.yar#L39-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "131b3666ae444e0de043eafdf7cfd3324b927d18d8ad56d5004ea09b2da5610e"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$CommonDLLs1 = "KERNEL32.dll" fullword
		$CommonDLLs2 = "USER32.dll" fullword
		$CommonDLLs3 = "ADVAPI32.dll" fullword
		$CommonDLLs4 = "ole32.dll" fullword
		$KeyString1 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 57 69 6E 64 6F 77 73 2E 43 6F 6D 6D 6F 6E 2D 43 6F 6E 74 72 6F 6C 73 22 20 76 65 72 73 69 6F 6E 3D 22 36 2E 30 2E 30 2E 30 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 22 }
		$KeyString2 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 56 43 39 30 2E 4D 46 43 22 20 76 65 72 73 69 6F 6E 3D 22 39 2E 30 2E 32 31 30 32 32 2E 38 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 31 66 63 38 62 33 62 39 61 31 65 31 38 65 33 62 22 }
		$Slashes = { 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C }

	condition:
		filesize <2MB and filesize >500KB and uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and ( all of ($CommonDLLs*)) and ( all of ($KeyString*)) and $Slashes
}