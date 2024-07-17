rule SIGNATURE_BASE_HKTL_NET_GUID_Sharptokenfinder : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "60fd06be-041b-5fa8-8f25-41b26605ea90"
		date = "2023-12-06"
		modified = "2024-04-24"
		reference = "https://github.com/HuskyHacks/SharpTokenFinder"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5508-L5520"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f9681a13b094b6e05cab69f0684d52e3bb3b465cfcdb1c83a890c9c8fda79169"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0 = "572804d3-dbd6-450a-be64-2e3cb54fd173" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}