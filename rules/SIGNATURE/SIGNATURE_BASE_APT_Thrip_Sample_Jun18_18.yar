rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_18 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "20642526-5a4d-5dca-a6f5-29f19a9b5271"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L345-L367"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5cac313bd77900e67f0528d660671394915dff7159ca6fa067fd9c392d7c269a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "33029f5364209e05481cfb2a4172c6dc157b0070f51c05dd34485b8e8da6e820"
		hash2 = "263c01a3b822722dc288a5ac138d953630d8c548a0bee080ae3979b7d364cecb"
		hash3 = "52d190a8d20b4845551b8765cbd12cfbe04cf23e6812e238e5a5023c34ee9b37"
		hash4 = "1f019e3c30a02b7b65f7984903af11d561d02b2666cc16463c274a2a0e62145d"
		hash5 = "43904ea071d4dce62a21c69b8d6efb47bcb24c467c6f6b3a6a6ed6cd2158bfe5"
		hash6 = "00d9da2b665070d674acdbb7c8f25a01086b7ca39d482d55f08717f7383ee26a"

	strings:
		$s1 = "Windows 95/98/Me, Windows NT 4.0, Windows 2000/XP: IME PROCESS key" fullword ascii
		$s2 = "Windows 2000/XP: Either the angle bracket key or the backslash key on the RT 102-key keyboard" fullword ascii
		$s3 = "LoadLibraryA() failed in KbdGetProcAddressByName()" fullword ascii
		$s5 = "Unknown Virtual-Key Code" fullword ascii
		$s6 = "Computer Sleep key" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}