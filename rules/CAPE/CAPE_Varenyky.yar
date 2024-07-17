rule CAPE_Varenyky : FILE
{
	meta:
		description = "Varenyky Payload"
		author = "kevoreilly"
		id = "e01695fa-72a0-5d8e-86ab-8c909d28b8ec"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Varenyky.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "602f1b8b60b29565eabe2171fde4eb58546af68f8acecad402a7a51ea9a08ed9"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Varenyky Payload"

	strings:
		$onion = "jg4rli4xoagvvmw47fr2bnnfu7t2epj6owrgyoee7daoh4gxvbt3bhyd.onion"

	condition:
		uint16(0)==0x5A4D and ($onion)
}