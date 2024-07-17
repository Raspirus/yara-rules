rule DITEKSHEN_INDICATOR_TOOL_Gogoscan : FILE
{
	meta:
		description = "Detects GoGo scan tool"
		author = "ditekSHen"
		id = "c24ede04-2971-55f8-8b60-ec3bdca844d7"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1621-L1635"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "c9fbc98a28c74bf920f5f7d62713834d18b33b5c65483a1bd42e4555764c8346"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "(conn) (scan  (scan) MB in  Value>" ascii
		$s2 = "sweep sysmontargettelnet" ascii
		$s3 = "%d bytes(?i) (.*SESS.*?ID)([a-z0-9])([A-Z]+)" ascii
		$s4 = "prepareForSweep" ascii
		$s5 = "Scanned %s with %d ports, found %d" ascii
		$s6 = "/chainreactors/gogo/" ascii
		$s7 = "Starting task %s ,total ports: %d , mod: %s" ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}