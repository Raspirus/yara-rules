rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcrasheventlog : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "85d31989-ad96-5005-a747-8a19a67fdd80"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/slyd0g/SharpCrashEventLog"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4811-L4825"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5f286244243024d23a6a27e5713a7ecedef9028b317d5827f35254a35e6c5473"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "98cb495f-4d47-4722-b08f-cefab2282b18" ascii wide
		$typelibguid0up = "98CB495F-4D47-4722-B08F-CEFAB2282B18" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}