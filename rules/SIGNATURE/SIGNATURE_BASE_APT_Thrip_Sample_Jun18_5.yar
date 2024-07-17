rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_5 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "42c56ed6-a509-568f-a611-ce7e5c5d9d8e"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L87-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6f2d4cfd55017ebb34fb6e8ad1b0b46b184926c69d4bacee88dc639771f96792"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "32889639a27961497d53176765b3addf9fff27f1c8cc41634a365085d6d55920"

	strings:
		$s2 = "c:\\windows\\USBEvent.exe" fullword ascii
		$s5 = "c:\\windows\\spdir.dat" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}