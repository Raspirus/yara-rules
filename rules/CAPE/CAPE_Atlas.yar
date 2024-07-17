
rule CAPE_Atlas : FILE
{
	meta:
		description = "Atlas Payload"
		author = "kevoreilly"
		id = "22322e5c-ded6-56df-8a39-a8f5cbc18239"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Atlas.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "c3f73b29df5caf804dbfe3e6ac07a9e2c772bd2a126f0487e4a65e72bd501e6e"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Atlas Payload"

	strings:
		$a1 = "bye.bat"
		$a2 = "task=knock&id=%s&ver=%s x%s&disks=%s&other=%s&ip=%s&pub="
		$a3 = "process call create \"cmd /c start vssadmin delete shadows /all /q"

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}