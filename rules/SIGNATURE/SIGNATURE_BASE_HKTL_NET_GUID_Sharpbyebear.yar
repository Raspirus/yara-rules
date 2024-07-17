import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpbyebear : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "4a7f2514-2519-5fd5-9d17-110a67f829e7"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpByeBear"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4761-L4777"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c6d9fd33dd8d7bddd9e80e3c0106f0cab13f0952bb8269a10df147c06a5bd7ba"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a6b84e35-2112-4df2-a31b-50fde4458c5e" ascii wide
		$typelibguid0up = "A6B84E35-2112-4DF2-A31B-50FDE4458C5E" ascii wide
		$typelibguid1lo = "3e82f538-6336-4fff-aeec-e774676205da" ascii wide
		$typelibguid1up = "3E82F538-6336-4FFF-AEEC-E774676205DA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}