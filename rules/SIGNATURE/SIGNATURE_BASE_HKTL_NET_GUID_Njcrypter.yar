import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Njcrypter : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c30c8323-9418-521a-a4fc-6be0113b99b5"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/0xPh0enix/njCrypter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L362-L378"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3fafad2f64c931394f9deddc1751da8286d7ba7727c3505fbc20cf8c4226971a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii wide
		$typelibguid0up = "8A87B003-4B43-467B-A509-0C8BE05BF5A5" ascii wide
		$typelibguid1lo = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii wide
		$typelibguid1up = "80B13BFF-24A5-4193-8E51-C62A414060EC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}