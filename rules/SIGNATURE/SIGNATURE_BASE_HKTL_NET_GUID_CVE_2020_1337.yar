rule SIGNATURE_BASE_HKTL_NET_GUID_CVE_2020_1337 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "4b79867d-761c-5aa8-bf8a-60caa50d8aa6"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/neofito/CVE-2020-1337"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2355-L2369"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f9a7d47861d19bb312cd75cd2edf66c8df02a0685a3eb5a1dd413e7b1c3c8234"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "d9c2e3c1-e9cc-42b0-a67c-b6e1a4f962cc" ascii wide
		$typelibguid0up = "D9C2E3C1-E9CC-42B0-A67C-B6E1A4F962CC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}