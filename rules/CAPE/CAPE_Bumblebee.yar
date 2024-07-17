rule CAPE_Bumblebee : FILE
{
	meta:
		description = "BumbleBee Payload"
		author = "enzo & kevoreilly"
		id = "b3a4dd53-014c-5e16-8ac1-7f3800ae017d"
		date = "2023-10-02"
		modified = "2023-10-02"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/BumbleBee.yar#L35-L50"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "bc7c2ce9d3cd598c9510dc64d78048999f2f89ee5a84cd0d6046dbdfabe260ee"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "BumbleBee Payload"

	strings:
		$antivm1 = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
		$antivm2 = {84 C0 0F 85 [2] 00 00 33 C9 E8 [4] 48 8B C8 E8 [4] 48 8D 85}
		$antivm3 = {33 C9 E8 [4] 48 8B C8 E8 [4] 83 CA FF 48 8B 0D [4] FF 15}
		$antivm4 = {33 C9 E8 [4] 48 8B C8 E8 [4] 90 48 8B 05 [4] 48 85 C0 74}
		$str_ua = "bumblebee"
		$str_gate = "/gate"

	condition:
		uint16(0)==0x5A4D and ( any of ($antivm*) or all of ($str_*))
}