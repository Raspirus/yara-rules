
rule CAPE_Fareit : FILE
{
	meta:
		description = "Fareit Payload"
		author = "kevoreilly"
		id = "b3c4eb86-d104-5f31-afa4-5bf5f370f64e"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Fareit.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "ed35391ffc949219f380da3f22bc8397a7d5c742bd68e227c3becdebcab5cf83"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Fareit Payload"

	strings:
		$string1 = {0D 0A 09 09 0D 0A 0D 0A 09 20 20 20 3A 6B 74 6B 20 20 20 0D 0A 0D 0A 0D 0A 20 20 20 20 20 64 65 6C 20 20 20 20 09 20 25 31 20 20 0D 0A 09 69 66 20 20 09 09 20 65 78 69 73 74 20 09 20 20 20 25 31 20 20 09 20 20 67 6F 74 6F 20 09 0D 20 6B 74 6B 0D 0A 20 64 65 6C 20 09 20 20 25 30 20 00}

	condition:
		uint16(0)==0x5A4D and any of ($string*)
}