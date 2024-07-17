rule DITEKSHEN_INDICATOR_TOOL_LTM_Ladon : FILE
{
	meta:
		description = "Detect Ladon tool that assists in lateral movement across a network"
		author = "ditekSHen"
		id = "227e63ce-8383-5bb1-870e-6c4e767b402f"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1162-L1178"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f31276bcbcae672966cfddc9af4f5b507d7244360b421de7fe1e811fb954fb7d"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$d1 = "Ladon.VncSharp.dll" fullword ascii
		$d2 = "Ladon.Renci.SshNet.dll" fullword ascii
		$s1 = "Ladon." ascii
		$s2 = "nowPos" fullword ascii
		$s3 = "Scan" fullword ascii
		$s4 = "QLZ_STREAMING_BUFFER" fullword ascii
		$s5 = "sizeDecompressed" fullword ascii
		$s6 = "UpdateByte" fullword ascii
		$s7 = "kNumBitPriceShiftBits" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($d*) or all of ($s*) or (1 of ($d*) and 5 of ($s*)))
}