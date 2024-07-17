import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sneakyexec : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "853b630d-77ba-5847-a129-c9fa0538f81b"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/HackingThings/SneakyExec"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L506-L520"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a1a88512f8da078f9eb4ece21106b1cb0ba99ad86f5d3f90b036b647bb396fd4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii wide
		$typelibguid0up = "612590AA-AF68-41E6-8CE2-E831F7FE4CCC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}