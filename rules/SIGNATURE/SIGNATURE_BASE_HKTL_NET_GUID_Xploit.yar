rule SIGNATURE_BASE_HKTL_NET_GUID_Xploit : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "11ba6c14-06b6-5d9f-ac69-08ae506877e7"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/shargon/Xploit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2649-L2683"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b049d1fe26677b8c1a5bfcb46bfa2b35073f2b4bba02551b490a527df81f145b"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4545cfde-9ee5-4f1b-b966-d128af0b9a6e" ascii wide
		$typelibguid0up = "4545CFDE-9EE5-4F1B-B966-D128AF0B9A6E" ascii wide
		$typelibguid1lo = "33849d2b-3be8-41e8-a1e2-614c94c4533c" ascii wide
		$typelibguid1up = "33849D2B-3BE8-41E8-A1E2-614C94C4533C" ascii wide
		$typelibguid2lo = "c2dc73cc-a959-4965-8499-a9e1720e594b" ascii wide
		$typelibguid2up = "C2DC73CC-A959-4965-8499-A9E1720E594B" ascii wide
		$typelibguid3lo = "77059fa1-4b7d-4406-bc1a-cb261086f915" ascii wide
		$typelibguid3up = "77059FA1-4B7D-4406-BC1A-CB261086F915" ascii wide
		$typelibguid4lo = "a4a04c4d-5490-4309-9c90-351e5e5fd6d1" ascii wide
		$typelibguid4up = "A4A04C4D-5490-4309-9C90-351E5E5FD6D1" ascii wide
		$typelibguid5lo = "ca64f918-3296-4b7d-9ce6-b98389896765" ascii wide
		$typelibguid5up = "CA64F918-3296-4B7D-9CE6-B98389896765" ascii wide
		$typelibguid6lo = "10fe32a0-d791-47b2-8530-0b19d91434f7" ascii wide
		$typelibguid6up = "10FE32A0-D791-47B2-8530-0B19D91434F7" ascii wide
		$typelibguid7lo = "679bba57-3063-4f17-b491-4f0a730d6b02" ascii wide
		$typelibguid7up = "679BBA57-3063-4F17-B491-4F0A730D6B02" ascii wide
		$typelibguid8lo = "0981e164-5930-4ba0-983c-1cf679e5033f" ascii wide
		$typelibguid8up = "0981E164-5930-4BA0-983C-1CF679E5033F" ascii wide
		$typelibguid9lo = "2a844ca2-5d6c-45b5-963b-7dca1140e16f" ascii wide
		$typelibguid9up = "2A844CA2-5D6C-45B5-963B-7DCA1140E16F" ascii wide
		$typelibguid10lo = "7d75ca11-8745-4382-b3eb-c41416dbc48c" ascii wide
		$typelibguid10up = "7D75CA11-8745-4382-B3EB-C41416DBC48C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}