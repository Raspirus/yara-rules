
rule SIGNATURE_BASE_MAL_ELF_Vpnfilter_1 : FILE
{
	meta:
		description = "Detects VPNFilter malware"
		author = "Florian Roth (Nextron Systems)"
		id = "dc50cb37-a6e7-5eb5-9581-31d7fd005e47"
		date = "2018-05-24"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_vpnfilter.yar#L11-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "aff7b1f3d4afaf883c2702287ef7d6e13e01e80222ba336978d13deb21a93614"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344"

	strings:
		$s1 = "Login=" fullword ascii
		$s2 = "Password=" fullword ascii
		$s3 = "%s/rep_%u.bin" fullword ascii
		$s4 = "%s:%uh->%s:%hu" fullword ascii
		$s5 = "Password required" fullword ascii
		$s6 = "password=" fullword ascii
		$s7 = "Authorization: Basic" fullword ascii
		$s8 = "/tmUnblock.cgi" fullword ascii

	condition:
		uint16(0)==0x457f and filesize <100KB and all of them
}