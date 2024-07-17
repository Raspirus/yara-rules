import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Nomsbuild : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9bc0661d-c60f-582b-8f88-87e3dfa13ddd"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rvrsh3ll/NoMSBuild"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3031-L3047"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3979162455153d586036960f3cf2a90a893541900245c4184e55631d2138ba75"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "034a7b9f-18df-45da-b870-0e1cef500215" ascii wide
		$typelibguid0up = "034A7B9F-18DF-45DA-B870-0E1CEF500215" ascii wide
		$typelibguid1lo = "59b449d7-c1e8-4f47-80b8-7375178961db" ascii wide
		$typelibguid1up = "59B449D7-C1E8-4F47-80B8-7375178961DB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}