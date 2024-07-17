rule CAPE_Azer : FILE
{
	meta:
		description = "Azer Payload"
		author = "kevoreilly"
		id = "4bda70c2-3cd9-543f-92f4-886b7dd899a1"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Azer.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "48bd4a4e071f10d1911c4173a0cd39c69fed7a3b29eb92beffe709899f4cefa5"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Azer Payload"

	strings:
		$a1 = "webmafia@asia.com" wide
		$a2 = "INTERESTING_INFORMACION_FOR_DECRYPT.TXT" wide
		$a3 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}