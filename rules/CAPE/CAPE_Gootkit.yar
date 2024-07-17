rule CAPE_Gootkit : FILE
{
	meta:
		description = "Gootkit Payload"
		author = "kevoreilly"
		id = "8935fd10-ac79-5196-80c2-fc8f2fe185b5"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Gootkit.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "26704b6b0adca51933fc9d5e097930320768fd0e9355dcefc725aee7775316e7"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Gootkit Payload"

	strings:
		$code1 = {C7 45 ?? ?? ?? 4? 00 C7 45 ?? ?? 10 40 00 C7 45 E? D8 ?? ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 [1-2] 00 10 40 00 89 [5-6] 43 00 89 ?? ?? 68 E8 80 00 00 FF 15}

	condition:
		uint16(0)==0x5A4D and all of them
}