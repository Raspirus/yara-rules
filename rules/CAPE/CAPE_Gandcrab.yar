
rule CAPE_Gandcrab : FILE
{
	meta:
		description = "Gandcrab Payload"
		author = "kevoreilly"
		id = "0082e8c9-952e-508c-a438-4e17b8031864"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Gandcrab.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "354ed566dbafbe8e9531bb771d9846952eb8c0e70ee94c26d09368159ce4142c"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Gandcrab Payload"

	strings:
		$string1 = "GDCB-DECRYPT.txt" wide
		$string2 = "GandCrabGandCrabnomoreransom.coinomoreransom.bit"
		$string3 = "action=result&e_files=%d&e_size=%I64u&e_time=%d&" wide
		$string4 = "KRAB-DECRYPT.txt" wide

	condition:
		uint16(0)==0x5A4D and any of ($string*)
}