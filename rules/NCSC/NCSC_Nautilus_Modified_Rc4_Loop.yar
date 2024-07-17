rule NCSC_Nautilus_Modified_Rc4_Loop : FILE
{
	meta:
		description = "Rule for detection of Nautilus based on assembly code for a modified RC4 loop"
		author = "NCSC UK"
		id = "0c5da057-0f1d-5852-ad75-94bf40c133e4"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L68-L79"
		license_url = "N/A"
		hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
		logic_hash = "58673db1d995ac2fed1eefa8baab426558bb9d46b239cdc8715d41925d5f4657"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$a = {42 0F B6 14 04 41 FF C0 03 D7 0F B6 CA 8A 14 0C 43 32 14 13 41 88 12 49 FF C2 49 FF C9}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $a
}