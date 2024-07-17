rule CAPE_Kovter : FILE
{
	meta:
		description = "Kovter Payload"
		author = "kevoreilly"
		id = "3dec3c4b-4678-5ed1-a4c3-c3d9abb58b1c"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Kovter.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "888fccb8fbfbe6c05ec63bc5658b4743f8e10a96ef51b3868c2ff94afec76f2d"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Kovter Payload"

	strings:
		$a1 = "chkok"
		$a2 = "k2Tdgo"
		$a3 = "13_13_13"
		$a4 = "Win Server 2008 R2"

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}