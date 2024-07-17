rule CAPE_Mole : FILE
{
	meta:
		description = "Mole Payload"
		author = "kevoreilly"
		id = "1185170f-4a5b-5347-807b-ef2af98a1a09"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Mole.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "8be4d190d554a610360c0e04b33da59eb00319395e5b2000d580546ce6503786"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Mole Payload"

	strings:
		$a1 = ".mole0" wide
		$a2 = "_HELP_INSTRUCTION.TXT" wide
		$a3 = "-----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}