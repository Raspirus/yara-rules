rule SIGNATURE_BASE_HKTL_NET_GUID_Poshsecframework : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "a91620f3-3f21-525a-bc87-94d21cd126be"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/PoshSec/PoshSecFramework"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4064-L4080"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e0a35f5fc7a4c4ae8f09c7d4833faf55061984f9a7a920ec4219f04381f2053a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b1ac6aa0-2f1a-4696-bf4b-0e41cf2f4b6b" ascii wide
		$typelibguid0up = "B1AC6AA0-2F1A-4696-BF4B-0E41CF2F4B6B" ascii wide
		$typelibguid1lo = "78bfcfc2-ef1c-4514-bce6-934b251666d2" ascii wide
		$typelibguid1up = "78BFCFC2-EF1C-4514-BCE6-934B251666D2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}