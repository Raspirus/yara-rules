rule NCSC_Neuron2_Dotnet_Strings : FILE
{
	meta:
		description = "Rule for detection of the .NET payload for Neuron2 based on strings used"
		author = "NCSC"
		id = "a36e4009-e1a1-520a-9397-8b6f2ad4065a"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L161-L176"
		license_url = "N/A"
		hash = "83d8922e7a8212f1a2a9015973e668d7999b90e7000c31f57be83803747df015"
		logic_hash = "9a0e8a3b627fa46f11fb5bbf926665aed4de6250c5229c8acb59c784e66943e5"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$dotnetMagic = "BSJB" ascii
		$s1 = "http://*:80/W3SVC/" wide
		$s2 = "https://*:443/W3SVC/" wide
		$s3 = "neuron2.exe" ascii
		$s4 = "D:\\Develop\\sps\\neuron2\\neuron2\\obj\\Release\\neuron2.pdb" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $dotnetMagic and 2 of ($s*)
}