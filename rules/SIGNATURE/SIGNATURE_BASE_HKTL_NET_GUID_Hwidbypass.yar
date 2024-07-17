import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Hwidbypass : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "62b0541b-6eec-546e-8445-85d25bb0d784"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/yunseok/HWIDbypass"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1684-L1698"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "17d34d65e2867c054c7ef941c8f92a89c42f7d21a301fd5230970ac07d003d90"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "47e08791-d124-4746-bc50-24bd1ee719a6" ascii wide
		$typelibguid0up = "47E08791-D124-4746-BC50-24BD1EE719A6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}