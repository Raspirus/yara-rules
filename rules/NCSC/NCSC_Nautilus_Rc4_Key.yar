rule NCSC_Nautilus_Rc4_Key : FILE
{
	meta:
		description = "Rule for detection of Nautilus based on a hardcoded RC4 key"
		author = "NCSC UK"
		id = "124c8b95-46fb-5cc1-9b10-b10536e1781d"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L81-L92"
		license_url = "N/A"
		hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
		logic_hash = "215c0a20b3793411eea3cbf85a2e5ada8ce6b1f5aa8d84fc468a354c53df2b0c"
		score = 75
		quality = 78
		tags = "FILE"

	strings:
		$key = {31 42 31 34 34 30 44 39 30 46 43 39 42 43 42 34 36 41 39 41 43 39 36 34 33 38 46 45 45 41 38 42}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $key
}