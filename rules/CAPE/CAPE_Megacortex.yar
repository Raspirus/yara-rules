
rule CAPE_Megacortex : FILE
{
	meta:
		description = "MegaCortex Payload"
		author = "kevoreilly"
		id = "ea3dd937-2cb1-5b0f-98b8-154aacaf8650"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/MegaCortex.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "5de1d8241260070241c91b97f18feb2a90069e3b158e863e2d9f568799c244e6"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "MegaCortex Payload"

	strings:
		$str1 = ".megac0rtx" ascii wide
		$str2 = "vssadmin delete shadows /all" ascii
		$sha256 = {98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9}

	condition:
		uint16(0)==0x5A4D and all of them
}