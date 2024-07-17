
rule CAPE_Codoso : FILE
{
	meta:
		description = "Codoso Payload"
		author = "kevoreilly"
		id = "4c3d8d77-ffa9-576d-bf88-7b5a1bfd1811"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Codoso.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "32c9ed2ac29e8905266977a9ee573a252442d96fb9ec97d88642180deceec3f8"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Codoso Payload"

	strings:
		$a1 = "WHO_A_R_E_YOU?"
		$a2 = "DUDE_AM_I_SHARP-3.14159265358979"
		$a3 = "USERMODECMD"

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}