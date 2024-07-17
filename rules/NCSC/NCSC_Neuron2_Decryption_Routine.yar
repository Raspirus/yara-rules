
rule NCSC_Neuron2_Decryption_Routine : FILE
{
	meta:
		description = "Rule for detection of Neuron2 based on the routine used to decrypt the payload"
		author = "NCSC"
		id = "6fa43865-f970-57c0-81c7-e9c851e9453c"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L148-L159"
		license_url = "N/A"
		hash = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
		logic_hash = "27a9de186dd1a91e3e3c18a786e5604e46e8d2f6364d76fa441bff15eb1aed84"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$ = {81 FA FF 00 00 00 0F B6 C2 0F 46 C2 0F B6 0C 04 48 03 CF 0F B6 D1 8A 0C 14 8D 50 01 43 32 0C 13 41 88 0A 49 FF C2 49 83 E9 01}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of them
}