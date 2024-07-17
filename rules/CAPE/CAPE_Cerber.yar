rule CAPE_Cerber : FILE
{
	meta:
		description = "Cerber Payload"
		author = "kevoreilly"
		id = "edf08795-cf54-5822-8bc4-35cfba0fe8e8"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Cerber.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "16a8f808c28d3b142c079a305aba7f553f2452e439710bf610a06f8f2924d5a3"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Cerber Payload"

	strings:
		$code1 = {33 C0 66 89 45 8? 8D 7D 8? AB AB AB AB AB [0-2] 66 AB 8D 45 8? [0-3] E8 ?? ?? 00 00}

	condition:
		uint16(0)==0x5A4D and all of them
}