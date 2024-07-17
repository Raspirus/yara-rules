import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_16 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "58be9a1b-2228-5d7a-97c9-198cacbe1a66"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L301-L317"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "950ece29e8fd056e3506684bce9b16eb185d63c1b020e4911972f5fcbdadbe30"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2b1c1c6d82837dbbccd171a0413c1d761b1f7c3668a21c63ca06143e731f030e"

	strings:
		$s1 = "[%d] Failed, %08X" fullword ascii
		$s2 = "woqunimalegebi" fullword ascii
		$s3 = "[%d] Offset can not fetched." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and ( all of them or pe.imphash()=="c6a4c95d868a3327a62c9c45f5e15bbf")
}