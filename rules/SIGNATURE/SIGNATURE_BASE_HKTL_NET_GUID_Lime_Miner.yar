rule SIGNATURE_BASE_HKTL_NET_GUID_Lime_Miner : FILE
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d0631817-10a2-55bf-a41d-226fa0dcb9f9"
		date = "2020-12-30"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/Lime-Miner"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4351-L4365"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "57d75144415518c24e2a24fa933e9e205513e16c2ec062b2a3c715a0fa6415db"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "13958fb9-dfc1-4e2c-8a8d-a5e68abdbc66" ascii wide
		$typelibguid0up = "13958FB9-DFC1-4E2C-8A8D-A5E68ABDBC66" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}