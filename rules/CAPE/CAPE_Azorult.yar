rule CAPE_Azorult : FILE
{
	meta:
		description = "Azorult Payload"
		author = "kevoreilly"
		id = "ca76ec00-001f-56d0-bdbc-9dfd3239fba8"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Azorult.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "4691cf48d513d1965416b0cce1b6e19c8f7b393a940afd68b7c6ca8c0d125d90"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Azorult Payload"

	strings:
		$code1 = {C7 07 3C 00 00 00 8D 45 80 89 47 04 C7 47 08 20 00 00 00 8D 85 80 FE FF FF 89 47 10 C7 47 14 00 01 00 00 8D 85 00 FE FF FF 89 47 1C C7 47 20 80 00 00 00 8D 85 80 FD FF FF 89 47 24 C7 47 28 80 00 00 00 8D 85 80 F5 FF FF 89 47 2C C7 47 30 00 08 00 00 8D 85 80 F1 FF FF 89 47 34 C7 47 38 00 04 00 00 57 68 00 00 00 90}
		$string1 = "SELECT DATETIME( ((visits.visit_time/1000000)-11644473600),\"unixepoch\")"

	condition:
		uint16(0)==0x5A4D and all of them
}