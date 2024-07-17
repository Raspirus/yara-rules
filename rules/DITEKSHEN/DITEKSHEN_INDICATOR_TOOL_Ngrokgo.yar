rule DITEKSHEN_INDICATOR_TOOL_Ngrokgo : FILE
{
	meta:
		description = "Detects Go implementation variant for Ngrok"
		author = "ditekSHen"
		id = "b11f67c5-846d-57b2-8edc-521b2dc77503"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1473-L1488"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "4ec151661e3af922aba202c68392a2af17e2c4ed25a71a0b5aacc13fbfcc5c53"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "/codegangsta/inject" fullword wide
		$s2 = "go.ngrok.com/" ascii
		$s3 = "GetIsNgrokDomain" ascii
		$s4 = "GetNgrokMetering" ascii
		$s5 = "*cli.ngrokService" ascii
		$s6 = "GetAllowNgrokLink" ascii
		$s7 = "ngrok {{.Name}}{{if .Flags}}" ascii
		$s8 = "github.com/nikolay-ngrok/" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}