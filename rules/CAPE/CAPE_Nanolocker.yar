
rule CAPE_Nanolocker : FILE
{
	meta:
		description = "NanoLocker Payload"
		author = "kevoreilly"
		id = "6fff6a27-a153-5461-9a75-2253c2f7d408"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/NanoLocker.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "fe6c8a4e259c3c526f8f50771251f6762b2b92a4df2e8bfc705f282489f757db"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "NanoLocker Payload"

	strings:
		$a1 = "NanoLocker"
		$a2 = "$humanDeadline"
		$a3 = "Decryptor.lnk"

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}