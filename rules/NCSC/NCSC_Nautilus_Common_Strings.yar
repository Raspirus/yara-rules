
rule NCSC_Nautilus_Common_Strings : FILE
{
	meta:
		description = "Rule for detection of Nautilus based on common plaintext strings"
		author = "NCSC UK"
		id = "0e3af6ef-1a97-5324-a186-95e6f3d836f4"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L94-L110"
		license_url = "N/A"
		hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
		logic_hash = "28d664018e396d48928678de35ea95148ca1c6579efcb832c50606f43089a862"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$ = "nautilus-service.dll" ascii
		$ = "oxygen.dll" ascii
		$ = "config_listen.system" ascii
		$ = "ctx.system" ascii
		$ = "3FDA3998-BEF5-426D-82D8-1A71F29ADDC3" ascii
		$ = "C:\\ProgramData\\Microsoft\\Windows\\Caches\\{%s}.2.ver0x0000000000000001.db" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and 3 of them
}