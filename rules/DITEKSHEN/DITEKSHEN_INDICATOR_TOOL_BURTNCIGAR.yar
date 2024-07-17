rule DITEKSHEN_INDICATOR_TOOL_BURTNCIGAR : FILE
{
	meta:
		description = "Detects BURNTCIGAR a utility which terminates processes associated with endpoint security software"
		author = "ditekSHen"
		id = "b5260d7e-07ac-5633-b450-e2124cbba65b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1668-L1680"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "4977332a0b20b300a5fc34f0f8d56221f55b66783853306d803e91701cb7e6ec"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.TOOL.BURNTCIGAR"

	strings:
		$s1 = "Kill PID =" ascii
		$s2 = "CreateFile Error =" ascii
		$s3 = "\\KillAV" ascii
		$s4 = "DeviceIoControl" ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}