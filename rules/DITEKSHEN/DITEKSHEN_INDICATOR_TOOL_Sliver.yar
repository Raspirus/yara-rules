rule DITEKSHEN_INDICATOR_TOOL_Sliver : FILE
{
	meta:
		description = "Detects Sliver implant cross-platform adversary emulation/red team"
		author = "ditekSHen"
		id = "e0c5404b-8e6b-5c3a-9e37-56012c3802dd"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L882-L900"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "4f9442b74c84c7b4a8fcf93de2919d12efe2f41d0b4e8514b43822fba0962af2"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "github.com/bishopfox/sliver/protobuf/sliverpbb." ascii
		$s1 = ".commonpb.ResponseR" ascii
		$s2 = ".PortfwdProtocol" ascii
		$s3 = ".WGTCPForwarder" ascii
		$s4 = ".WGSocksServerR" ascii
		$s5 = ".PivotEntryR" ascii
		$s6 = ".BackdoorReq" ascii
		$s7 = ".ProcessDumpReq" ascii
		$s8 = ".InvokeSpawnDllReq" ascii
		$s9 = ".SpawnDll" ascii
		$s10 = ".TCPPivotReq" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f or uint16(0)==0xfacf) and (1 of ($x*) or 5 of ($s*))
}