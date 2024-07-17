rule CAPE_Nemty : FILE
{
	meta:
		description = "Nemty Ransomware Payload"
		author = "kevoreilly"
		id = "3aa8e1d7-f9cb-5b04-923d-7bed15ab8c3f"
		date = "2020-04-03"
		modified = "2020-04-03"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Nemty.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "a05974b561c67b4f1e0812639b74831edcf65686a06c0d380f0b45739e342419"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Nemty Payload"

	strings:
		$tordir = "TorDir"
		$decrypt = "DECRYPT.txt"
		$nemty = "NEMTY"

	condition:
		uint16(0)==0x5A4D and all of them
}