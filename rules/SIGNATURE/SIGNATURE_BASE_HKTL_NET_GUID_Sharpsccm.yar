import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpsccm : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "276269b1-e3b3-5774-a86a-1c3a8bca8209"
		date = "2023-03-15"
		modified = "2023-04-06"
		reference = "https://github.com/Mayyhem/SharpSCCM"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5116-L5132"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ce0d186ceb4212619d76f56b32e06efa78572af0d8abd881432928c1876b968b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "03652836-898e-4a9f-b781-b7d86e750f60" ascii wide
		$typelibguid0up = "03652836-898E-4A9F-B781-B7D86E750F60" ascii wide
		$typelibguid1lo = "e4d9ef39-0fce-4573-978b-abf8df6aec23" ascii wide
		$typelibguid1up = "E4D9EF39-0FCE-4573-978B-ABF8DF6AEC23" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}