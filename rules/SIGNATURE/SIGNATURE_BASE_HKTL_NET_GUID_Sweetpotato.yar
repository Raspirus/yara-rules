import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sweetpotato : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0e347d94-51eb-5589-93d8-b19fec7f2365"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/CCob/SweetPotato"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3437-L3453"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0a514be8ef3b51a3cad22a470afd9a4911c7156bfbf14f0a33522b429041e5bb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "6aeb5004-6093-4c23-aeae-911d64cacc58" ascii wide
		$typelibguid0up = "6AEB5004-6093-4C23-AEAE-911D64CACC58" ascii wide
		$typelibguid1lo = "1bf9c10f-6f89-4520-9d2e-aaf17d17ba5e" ascii wide
		$typelibguid1up = "1BF9C10F-6F89-4520-9D2E-AAF17D17BA5E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}