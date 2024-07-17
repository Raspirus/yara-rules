
rule SIGNATURE_BASE_Nanocore_RAT_Feb18_1 : FILE
{
	meta:
		description = "Detects Nanocore RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "6db0c8a7-8c31-58a6-8732-de6663fec16b"
		date = "2018-02-19"
		modified = "2023-12-05"
		reference = "Internal Research - T2T"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_nanocore_rat.yar#L92-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "824fd7304fb298ced69811078aa2dd23d7116554cffb8b6e4b690fccc93a4caf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "aa486173e9d594729dbb5626748ce10a75ee966481b68c1b4f6323c827d9658c"

	strings:
		$x1 = "NanoCore Client.exe" fullword ascii
		$x2 = "NanoCore.ClientPluginHost" fullword ascii
		$s1 = "PluginCommand" fullword ascii
		$s2 = "FileCommand" fullword ascii
		$s3 = "PipeExists" fullword ascii
		$s4 = "PipeCreated" fullword ascii
		$s5 = "IClientLoggingHost" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (1 of ($x*) or 5 of them )
}