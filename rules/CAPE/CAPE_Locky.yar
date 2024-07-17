
rule CAPE_Locky : FILE
{
	meta:
		description = "Locky Payload"
		author = "kevoreilly"
		id = "664d0365-af49-5222-a4ed-9260332f6940"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Locky.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "9786c54a2644d9581fefe64be11b26e22806398e54e961fa4f19d26eae039cd7"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Locky Payload"

	strings:
		$string1 = "wallet.dat" wide
		$string2 = "Locky_recover" wide
		$string3 = "opt321" wide

	condition:
		uint16(0)==0x5A4D and all of them
}