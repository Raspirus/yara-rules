rule SIGNATURE_BASE_HKTL_NET_GUID_Njrat : FILE
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2140d69e-fb15-50a2-ba85-b7c8293003fb"
		date = "2020-12-30"
		modified = "2023-04-06"
		reference = "https://github.com/mwsrc/njRAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4463-L4487"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "739914bf21b1ac198e904b50986e28a50e53044696dafa777149f18f024beb5e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "5a542c1b-2d36-4c31-b039-26a88d3967da" ascii wide
		$typelibguid0up = "5A542C1B-2D36-4C31-B039-26A88D3967DA" ascii wide
		$typelibguid1lo = "6b07082a-9256-42c3-999a-665e9de49f33" ascii wide
		$typelibguid1up = "6B07082A-9256-42C3-999A-665E9DE49F33" ascii wide
		$typelibguid2lo = "c0a9a70f-63e8-42ca-965d-73a1bc903e62" ascii wide
		$typelibguid2up = "C0A9A70F-63E8-42CA-965D-73A1BC903E62" ascii wide
		$typelibguid3lo = "70bd11de-7da1-4a89-b459-8daacc930c20" ascii wide
		$typelibguid3up = "70BD11DE-7DA1-4A89-B459-8DAACC930C20" ascii wide
		$typelibguid4lo = "fc790ee5-163a-40f9-a1e2-9863c290ff8b" ascii wide
		$typelibguid4up = "FC790EE5-163A-40F9-A1E2-9863C290FF8B" ascii wide
		$typelibguid5lo = "cb3c28b2-2a4f-4114-941c-ce929fec94d3" ascii wide
		$typelibguid5up = "CB3C28B2-2A4F-4114-941C-CE929FEC94D3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}