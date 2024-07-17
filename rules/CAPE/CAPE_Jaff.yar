
rule CAPE_Jaff : FILE
{
	meta:
		description = "Jaff Payload"
		author = "kevoreilly"
		id = "6681c1fe-6c88-5a49-bdfa-54ce08ea6707"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Jaff.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "6806a5eeee04b7436ff694addc334bfc0f1ee611116904d57be9506acfd47418"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Jaff Payload"

	strings:
		$a1 = "CryptGenKey"
		$a2 = "353260540318613681395633061841341670181307185694827316660016508"
		$b1 = "jaff"
		$b2 = "2~1c0q4t7"

	condition:
		uint16(0)==0x5A4D and ( any of ($a*)) and (1 of ($b*))
}