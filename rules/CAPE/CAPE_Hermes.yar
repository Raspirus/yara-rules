
rule CAPE_Hermes : FILE
{
	meta:
		description = "Hermes Payload"
		author = "kevoreilly"
		id = "0ff44422-9c14-517b-9e71-8e9e19694f06"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Hermes.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "9bc974173f39a57e7adfbf8ae106a20d960557696b4c3ce16e9b4e47d3e9e95b"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Hermes Payload"

	strings:
		$ext = ".HRM" wide
		$vss = "vssadmin Delete"
		$email = "supportdecrypt@firemail.cc" wide

	condition:
		uint16(0)==0x5A4D and all of ($*)
}