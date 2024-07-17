import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpnamedpipepth : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "561b95a5-f32b-5fe8-9e67-3f702306be93"
		date = "2023-11-30"
		modified = "2024-04-24"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5494-L5506"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "437a8a41073174e86f642717537bdeeb5343cc8683c95477a52d6801a46aac21"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0 = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}