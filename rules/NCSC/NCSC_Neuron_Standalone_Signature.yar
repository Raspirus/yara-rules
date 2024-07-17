
rule NCSC_Neuron_Standalone_Signature : FILE
{
	meta:
		description = "Rule for detection of Neuron based on a standalone signature from .NET metadata"
		author = "NCSC UK"
		id = "e0be2fe2-32fd-5bdf-bfac-a596264be7ba"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L25-L37"
		license_url = "N/A"
		hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
		logic_hash = "a0d8d7e834fb07c22951ea4a31bf507e0c3d471e7cd500b60096f5e09844b452"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$a = {eb073d151231011234080e12818d1d051281311d1281211d1281211d128121081d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281}
		$dotnetMagic = "BSJB" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of them
}