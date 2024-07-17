rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpexcel4_DCOM : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "12d3f26b-40ca-5034-a7c2-9be9c8a7599b"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rvrsh3ll/SharpExcel4-DCOM"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2999-L3013"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "abc87f0ed51f044633ef7854610cd16460eefad570c31c7fe854d245229cceb3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "68b83ce5-bbd9-4ee3-b1cc-5e9223fab52b" ascii wide
		$typelibguid0up = "68B83CE5-BBD9-4EE3-B1CC-5E9223FAB52B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}