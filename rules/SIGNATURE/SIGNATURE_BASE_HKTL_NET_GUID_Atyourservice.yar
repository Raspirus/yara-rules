rule SIGNATURE_BASE_HKTL_NET_GUID_Atyourservice : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3077dd0c-6936-5340-8da9-e8643de4d864"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/mitchmoser/AtYourService"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4709-L4723"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3e473ebb7e01cdc2edb9a20ba5ace39fd69629fb04d83510bc7855696c9ae581"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "bc72386f-8b4c-44de-99b7-b06a8de3ce3f" ascii wide
		$typelibguid0up = "BC72386F-8B4C-44DE-99B7-B06A8DE3CE3F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}