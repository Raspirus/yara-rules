rule SIGNATURE_BASE_HKTL_NET_GUID_Multios_Reverseshell : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f54bcb1a-b0cd-5988-bf1d-4fa6c012d6b9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/belane/MultiOS_ReverseShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1310-L1324"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ae5a41fd66f058a8f89f6b9d488d7f4a845bf7829a1eb04f49c4e8e4c8db1cc0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "df0dd7a1-9f6b-4b0f-801e-e17e73b0801d" ascii wide
		$typelibguid0up = "DF0DD7A1-9F6B-4B0F-801E-E17E73B0801D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}