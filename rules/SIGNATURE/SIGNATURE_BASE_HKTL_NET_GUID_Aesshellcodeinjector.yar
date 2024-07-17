import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Aesshellcodeinjector : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "6253e30b-7c92-5237-a706-e93403a7c0b6"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/san3ncrypt3d/AESShellCodeInjector"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5352-L5366"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a3a6793e5ba5788fb01b3a04dc287d0bad44c87c72da302e5629d59a35ee1583"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b016da9e-12a1-4f1d-91a1-d681ae54e92c" ascii wide
		$typelibguid0up = "B016DA9E-12A1-4F1D-91A1-D681AE54E92C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}