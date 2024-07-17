rule CAPE_Tscookie : FILE
{
	meta:
		description = "TSCookie Payload"
		author = "kevoreilly"
		id = "e1efd356-7170-5454-bf40-68927c71816c"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/TSCookie.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "0461c7fd14c74646437654f0a63a4a89d4efad620e197a8ca1e8d390618842c3"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "TSCookie Payload"

	strings:
		$string1 = "http://%s:%d" wide
		$string2 = "/Default.aspx" wide
		$string3 = "\\wship6"

	condition:
		uint16(0)==0x5A4D and all of them
}