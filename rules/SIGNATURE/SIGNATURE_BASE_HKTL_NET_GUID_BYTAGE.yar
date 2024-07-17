import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_BYTAGE : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "4f87ca2c-3ac1-5733-893e-79665b80ffc3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/KNIF/BYTAGE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1294-L1308"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "faf0172ab464c4a19ce5ba4514f2a60ac4e78ce20be4fb4878a23e2980b6ea88"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii wide
		$typelibguid0up = "8E46BA56-E877-4DEC-BE1E-394CB1B5B9DE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}