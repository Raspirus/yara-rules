
rule CAPE_Bazar : FILE
{
	meta:
		description = "No description has been set in the source file - CAPE"
		author = "kevoreilly"
		id = "e042f180-2a82-5c93-9858-77281557dd10"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Bazar.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "9375f59b56e47fd0b90b089afdf3be8f16f960038fc625523a2e2d5509ab099d"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Bazar Payload"

	strings:
		$decode = {F7 E9 [0-2] C1 FA 0? 8B C2 C1 E8 1F 03 D0 6B C2 ?? 2B C8}
		$rsa = {C7 00 52 53 41 33 48 8D 48 09 C7 40 04 00 08 00 00 4C 8D 05 [3] 00 C6 40 08 03 B8 09 00 00 00 [0-3] 48 8D 89 80 00 00 00 41 0F 10 00}

	condition:
		uint16(0)==0x5A4D and 2 of them
}