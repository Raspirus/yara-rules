rule SIGNATURE_BASE_HKTL_NET_GUID_Syscallpoc : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1ed5e226-0dcd-5397-b5e8-41f8a14981a1"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/SolomonSklash/SyscallPOC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2227-L2243"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "95f6c80e810c4f3b680958d8fe41983f965e47994ddc2f85756d570341b54bb9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "1e54637b-c887-42a9-af6a-b4bd4e28cda9" ascii wide
		$typelibguid0up = "1E54637B-C887-42A9-AF6A-B4BD4E28CDA9" ascii wide
		$typelibguid1lo = "198d5599-d9fc-4a74-87f4-5077318232ad" ascii wide
		$typelibguid1up = "198D5599-D9FC-4A74-87F4-5077318232AD" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}