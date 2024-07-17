rule CAPE_Seduploader : FILE
{
	meta:
		description = "Seduploader decrypt function"
		author = "kevoreilly"
		id = "a7152d8c-a197-5784-8a6d-453d41585df1"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Seduploader.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "d70c886699169d4dafc5b063c93682a34af5667df6d293b52256ddc19ab9c516"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Seduploader Payload"

	strings:
		$decrypt1 = {8D 0C 30 C7 45 FC 0A 00 00 00 33 D2 F7 75 FC 8A 82 ?? ?? ?? ?? 32 04 0F 88 01 8B 45 0C 40 89 45 0C 3B C3 7C DB}

	condition:
		uint16(0)==0x5A4D and any of ($decrypt*)
}