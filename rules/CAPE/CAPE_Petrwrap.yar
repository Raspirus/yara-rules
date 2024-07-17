
rule CAPE_Petrwrap : FILE
{
	meta:
		description = "PetrWrap Payload"
		author = "kevoreilly"
		id = "83762c87-6e96-50fe-b297-e1a5f893be43"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/PetrWrap.yar#L1-L15"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "6dd1cf5639b63d0ab41b24080dad68d285f2e3969ad34fd724c83e7a0dd4b968"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "PetrWrap Payload"

	strings:
		$a1 = "http://petya3jxfp2f7g3i.onion/"
		$a2 = "http://petya3sen7dyko2n.onion"
		$b1 = "http://mischapuk6hyrn72.onion/"
		$b2 = "http://mischa5xyix2mrhd.onion/"

	condition:
		uint16(0)==0x5A4D and ( any of ($a*)) and ( any of ($b*))
}