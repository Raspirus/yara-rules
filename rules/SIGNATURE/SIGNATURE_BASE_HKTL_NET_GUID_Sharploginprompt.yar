rule SIGNATURE_BASE_HKTL_NET_GUID_Sharploginprompt : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e9a493d9-21b6-5ff1-9e5e-e8fbacc34c0c"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/shantanu561993/SharpLoginPrompt"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L186-L200"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a34873666a7a4a8aff77281fe638b1fd244f5295702cf815846ff64bcc21e360"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c12e69cd-78a0-4960-af7e-88cbd794af97" ascii wide
		$typelibguid0up = "C12E69CD-78A0-4960-AF7E-88CBD794AF97" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}