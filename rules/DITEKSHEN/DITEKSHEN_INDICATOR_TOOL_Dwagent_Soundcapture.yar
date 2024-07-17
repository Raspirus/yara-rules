import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Dwagent_Soundcapture : FILE
{
	meta:
		description = "Detect DWAgent Remote Administration Tool Sound Capture Module"
		author = "ditekSHen"
		id = "4e395d1e-96a1-5ecc-abe5-6f8323a2c8ca"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1577-L1587"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "c0efa9f383373dec1c5b9d127c2b4c6f4906718ae8f62eea28d7a369001be5af"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "DWASoundCapture" ascii
		$s2 = /_Z\d{2}DWASoundCapture/ ascii
		$s3 = "_Z6recordPvS_" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}