import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpldaprelayscan : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "554a5487-ac53-512f-8f6f-ad8186144715"
		date = "2023-03-15"
		modified = "2023-04-06"
		reference = "https://github.com/klezVirus/SharpLdapRelayScan"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5084-L5098"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "853b8b7e797a4be85f5218ad2f54dd4a91812e9e53ad061ca3e849326a8f9189"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a93ee706-a71c-4cc1-bf37-f26c27825b68" ascii wide
		$typelibguid0up = "A93EE706-A71C-4CC1-BF37-F26C27825B68" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}