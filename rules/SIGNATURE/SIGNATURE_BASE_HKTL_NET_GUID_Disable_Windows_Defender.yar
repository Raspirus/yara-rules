rule SIGNATURE_BASE_HKTL_NET_GUID_Disable_Windows_Defender : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9a673427-e66e-594b-942a-64a2272319f3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/Disable-Windows-Defender"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L430-L444"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "eeabc349036a73e65f81558e5e447c69a68161d487d0991a808800135287a67c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "501e3fdc-575d-492e-90bc-703fb6280ee2" ascii wide
		$typelibguid0up = "501E3FDC-575D-492E-90BC-703FB6280EE2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}