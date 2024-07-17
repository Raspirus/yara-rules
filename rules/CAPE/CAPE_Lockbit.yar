rule CAPE_Lockbit : FILE
{
	meta:
		description = "Lockbit Payload"
		author = "kevoreilly"
		id = "ec9b4fec-0233-5277-b922-07057c2b4b34"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Lockbit.yar#L1-L15"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "80ab705c8246a0bd5b3de65146cf32b102f39bf9444bdf1d366b5a794c1229b9"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Lockbit Payload"

	strings:
		$string1 = "/C ping 127.0.0.7 -n 3 > Nul & fsutil file setZeroData offset=0 length=524288 \"%s\" & Del /f /q \"%s\"" wide
		$string2 = "Ransom" ascii wide
		$crypto = {8B 4D 08 C1 E9 10 0F B6 D1 8B 4D 0C C1 E9 08 0F B6 C9 8B 14 95 [4] 8B 7D FC 33 14 8D [4] 8B CF C1 E9 18 33 14 8D [4] 0F B6 CB 33 14 8D [4] 8B CF 33 10}
		$decode1 = {8A ?4 34 ?C 0? 00 00 8B 8? 24 ?8 0? 00 00 0F BE ?? 0F BE C? 33 ?? 88 ?? 34 ?? 0? 00 00 46 83 FE 0? 72 DD}
		$decode2 = {8A 44 24 ?? 30 44 0C ?? 41 83 F9 ?? 72 F2}

	condition:
		uint16(0)==0x5A4D and (2 of them )
}