
rule NCSC_Neuron2_Loader_Strings : FILE
{
	meta:
		description = "Rule for detection of Neuron2 based on strings within the loader"
		author = "NCSC"
		id = "eaef4710-1971-55a2-9079-07a9b8bd86eb"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L130-L146"
		license_url = "N/A"
		hash = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
		logic_hash = "c873eaf6f00ea1ee7d86dad451b997d4c8c45c27ac07c3a222b57b5dc203a810"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$ = "dcom_api" ascii
		$ = "http://*:80/OWA/OAB/" ascii
		$ = "https://*:443/OWA/OAB/" ascii
		$ = "dcomnetsrv.cpp" wide
		$ = "dcomnet.dll" ascii
		$ = "D:\\Develop\\sps\\neuron2\\x64\\Release\\dcomnet.pdb" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and 2 of them
}