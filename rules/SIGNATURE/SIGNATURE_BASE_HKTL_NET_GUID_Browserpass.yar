import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Browserpass : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "bad36c36-dbed-527c-a2f5-4dceff1abe4b"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/jabiel/BrowserPass"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4148-L4162"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "70414002857991016ebd01889d6346b32a553525e06556f5273e53753c3caccc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "3cb59871-0dce-453b-857a-2d1e515b0b66" ascii wide
		$typelibguid0up = "3CB59871-0DCE-453B-857A-2D1E515B0B66" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}