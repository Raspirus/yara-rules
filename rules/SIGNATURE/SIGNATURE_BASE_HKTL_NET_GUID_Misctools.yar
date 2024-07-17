import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Misctools : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ce49cc7b-a5a5-52b7-a7bf-bbb0c5b29b8a"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rasta-mouse/MiscTools"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3699-L3721"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "551c11eb44007cefd7e588fa97659cea44cf64b32a2e061aab425aa4a67583ef"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "384e9647-28a9-4835-8fa7-2472b1acedc0" ascii wide
		$typelibguid0up = "384E9647-28A9-4835-8FA7-2472B1ACEDC0" ascii wide
		$typelibguid1lo = "d7ec0ef5-157c-4533-bbcd-0fe070fbf8d9" ascii wide
		$typelibguid1up = "D7EC0EF5-157C-4533-BBCD-0FE070FBF8D9" ascii wide
		$typelibguid2lo = "10085d98-48b9-42a8-b15b-cb27a243761b" ascii wide
		$typelibguid2up = "10085D98-48B9-42A8-B15B-CB27A243761B" ascii wide
		$typelibguid3lo = "6aacd159-f4e7-4632-bad1-2ae8526a9633" ascii wide
		$typelibguid3up = "6AACD159-F4E7-4632-BAD1-2AE8526A9633" ascii wide
		$typelibguid4lo = "49a6719e-11a8-46e6-ad7a-1db1be9fea37" ascii wide
		$typelibguid4up = "49A6719E-11A8-46E6-AD7A-1DB1BE9FEA37" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}