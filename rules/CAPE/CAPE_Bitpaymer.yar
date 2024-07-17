rule CAPE_Bitpaymer : FILE
{
	meta:
		description = "BitPaymer Payload"
		author = "kevoreilly"
		id = "c139b514-a1ba-5d47-8f4d-8e60cddfe2ba"
		date = "2019-11-27"
		modified = "2019-11-27"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/BitPaymer.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "6ae0dc9a36da13e483d8d653276b06f59ecc15c95c754c268dcc91b181677c4c"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "BitPaymer Payload"

	strings:
		$decrypt32 = {6A 40 58 3B C8 0F 4D C1 39 46 04 7D 50 53 57 8B F8 81 E7 3F 00 00 80 79 05 4F 83 CF C0 47 F7 DF 99 1B FF 83 E2 3F 03 C2 F7 DF C1 F8 06 03 F8 C1 E7 06 57}
		$antidefender = "TouchMeNot" wide

	condition:
		uint16(0)==0x5A4D and all of them
}