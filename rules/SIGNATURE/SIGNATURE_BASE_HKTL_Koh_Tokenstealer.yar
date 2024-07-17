
rule SIGNATURE_BASE_HKTL_Koh_Tokenstealer : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project."
		author = "Will Schroeder (@harmj0y)"
		id = "76b6cc9f-5db7-5e9b-939c-e713bad8137a"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/GhostPack/Koh"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_hktl_koh_tokenstealer.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e2c4d948e23f1a3a92689f35fedde6e041d09cd88deac9ff3249556be0b8f789"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x_typelibguid = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii
		$s1 = "[*] Already SYSTEM, not elevating" wide fullword
		$s2 = "S-1-[0-59]-\\d{2}-\\d{8,10}-\\d{8,10}-\\d{8,10}-[1-9]\\d{2}" wide
		$s3 = "0x[0-9A-Fa-f]+$" wide
		$s4 = "\\Koh.pdb" ascii

	condition:
		uint16(0)==0x5A4D and 1 of ($x*) or 3 of them
}