
rule DITEKSHEN_INDICATOR_KB_Gobuildid_Snatch : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "6ab6b7bc-c905-5ff9-8059-a2d512ba13b3"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1600-L1610"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "5a19c791ed0d829c4c97e35cfa604a8716bad3f02632712903d765db95ba87f6"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"8C2VvDTH-MuUPx8tL42E/PWF9iuE2j_Zt0ANsTlty/c64swZ5TtuaIpHuEFmga/6sS0KWNryc-YAduDnWWO\"" ascii
		$s2 = "Go build ID: \"UBrfJ_wztDfCHWakqvlV/LhzfkJwvKFrNhKCHtU9_/sveCupt8GVbvu6WZiyA-/GcimfL_TPl6FTPPriBDr\"" ascii
		$s3 = "Go build ID: \"5zCy9jt7UZaIs5YPk4tt/1Yt6v7gCpDG---pRFyW-/7729nLSeKJik31ftz_Ve/Z5EVG3lWak3ynxNrJ4ih\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}