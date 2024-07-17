import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Adfsdump : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8cb2edcd-3696-5857-90ca-e99b1af54320"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/fireeye/ADFSDump"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3903-L3917"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5bf4c506a39a3ad33a19ab40ce85e6fb7c7efeab154444b14f008c22529b0779"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9ee27d63-6ac9-4037-860b-44e91bae7f0d" ascii wide
		$typelibguid0up = "9EE27D63-6AC9-4037-860B-44E91BAE7F0D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}