
rule CAPE_Petya : FILE
{
	meta:
		description = "Petya Payload"
		author = "kevoreilly"
		id = "e581747c-c40f-5689-84b4-d55134b532f7"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Petya.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "f819261bb34f3b2eb7dc2f843b56be25105570fe902a77940a632a54fbe0d014"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Petya Payload"

	strings:
		$a1 = "CHKDSK is repairing sector"
		$a2 = "wowsmith123456@posteo.net"
		$a3 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" wide

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}