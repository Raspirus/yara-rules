rule SIGNATURE_BASE_HKTL_NET_GUID_Keystrokeapi : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e715bce8-531b-5e2a-bd02-b2fc4990c499"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L670-L686"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e638c173817ce6e1b59bfd897ba3d45e24a5c1020014999e2ad21afcd4f21291"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii wide
		$typelibguid0up = "F6FEC17E-E22D-4149-A8A8-9F64C3C905D3" ascii wide
		$typelibguid1lo = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii wide
		$typelibguid1up = "B7AA4E23-39A4-49D5-859A-083C789BFEA2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}