import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Redsharp : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2aa62d61-075c-5664-a7fc-2b9d84b954ed"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/padovah4ck/RedSharp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L924-L938"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b611422c3bd8d3ed713cbeabadef0402dfdee42e8bbe563b054dc582945d8519"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii wide
		$typelibguid0up = "30B2E0CF-34DD-4614-A5CA-6578FB684AEA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}