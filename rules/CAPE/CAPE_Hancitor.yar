rule CAPE_Hancitor : FILE
{
	meta:
		description = "Hancitor Payload"
		author = "threathive"
		id = "b4e9a26a-db00-5553-acc2-f35148b0ffd5"
		date = "2020-10-20"
		modified = "2020-10-20"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Hancitor.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "84003542a2f587b5fbd43731c4240759806f8ee46df2bd96aae4a3c09d97e41c"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Hancitor Payload"

	strings:
		$fmt_string = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
		$fmt_string2 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
		$ipfy = "http://api.ipify.org"
		$user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		uint16(0)==0x5A4D and all of them
}