
rule CAPE_Agentteslav4 : FILE
{
	meta:
		description = "AgentTesla Payload"
		author = "kevoreilly"
		id = "a39109ca-84cb-527d-b9c2-d8763fa6e496"
		date = "2024-03-22"
		modified = "2024-03-22"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/AgentTesla.yar#L125-L138"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "0a39036f408728ab312a54ff3354453d171424f57f9a8f3b42af867be3037ca9"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "AgentTesla Payload"
		packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"

	strings:
		$decode1 = {(07|FE 0C 01 00) (07|FE 0C 01 00) 8E 69 (17|20 01 00 00 00) 63 8F ?? 00 00 01 25 47 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A D2 61 D2 52}
		$decode2 = {(07|FE 0C 01 00) (08|FE 0C 02 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (11 07|FE 0C 07 00) 91 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A 61 D2 61 D2 52}
		$decode3 = {(07|FE 0C 01 00) (11 07|FE 0C 07 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (08|FE 0C 02 00) 91 61 D2 52}

	condition:
		uint16(0)==0x5A4D and all of them
}