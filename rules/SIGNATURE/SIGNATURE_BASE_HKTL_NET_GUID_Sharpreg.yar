rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpreg : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d89b07b0-bb29-5c77-888b-322e439b4c82"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/jnqpblc/SharpReg"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4657-L4671"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "dfe9189c215c090bc32dedfb0d01964409265a4da4e4f8c4a2ed9ee62b1c9b30"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8ef25b00-ed6a-4464-bdec-17281a4aa52f" ascii wide
		$typelibguid0up = "8EF25B00-ED6A-4464-BDEC-17281A4AA52F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}