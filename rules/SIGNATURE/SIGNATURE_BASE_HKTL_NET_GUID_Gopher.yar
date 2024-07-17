import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Gopher : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e3015719-9085-584d-8237-f377ec995149"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/EncodeGroup/Gopher"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L330-L344"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f17688d229c74f0f956a45d9eacfa2bb190c973c097bc870db96edc5c331f436"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii wide
		$typelibguid0up = "B5152683-2514-49CE-9ACA-1BC43DF1E234" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}