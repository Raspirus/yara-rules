import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Certify : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "69f120fe-bd4d-59ba-b1b9-528ab300e450"
		date = "2023-03-06"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/Certify"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5047-L5062"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "da585a8d4985082873cb86204d546d3f53668e034c61e42d247b11e92b5e8fc3"
		logic_hash = "bd856a146f441f28d8190d29b3168794cf2b68292869858c763200ae529615da"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii wide
		$typelibguid0up = "64524CA5-E4D0-41B3-ACC3-3BDBEFD40C97" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}