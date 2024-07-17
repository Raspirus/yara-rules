import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Shellcoderunner : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "949364e7-dcb6-5afd-ade9-cc34a6e15e97"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/antman1p/ShellCodeRunner"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L688-L704"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "48dfe2ea9b3ff1ae22c5436b8cb3f3f48658032c94463e2babeb6894ce3c666f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii wide
		$typelibguid0up = "634874B7-BF85-400C-82F0-7F3B4659549A" ascii wide
		$typelibguid1lo = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii wide
		$typelibguid1up = "2F9C3053-077F-45F2-B207-87C3C7B8F054" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}