
rule SIGNATURE_BASE_HKTL_NET_NAME_Ghostpack_Compiledbinaries : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "7cc81894-8c01-5a17-a7ed-1cb4cf1e2d53"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L342-L355"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a8e90f07b7d1ec309e51e3606169a05c4bb2b2aa7e31ca26b21f927d648c13cd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "Ghostpack-CompiledBinaries" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}