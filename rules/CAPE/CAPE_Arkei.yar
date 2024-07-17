rule CAPE_Arkei : FILE
{
	meta:
		description = "Arkei Payload"
		author = "kevoreilly"
		id = "22ebe194-19a9-5bf2-9cfc-ea27b7724572"
		date = "2020-02-11"
		modified = "2020-02-11"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Arkei.yar#L1-L24"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "03980827db1c53d4090ab196ba820ca34b5d83dc7140b11ead9182cb5d28c7d3"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Arkei Payload"

	strings:
		$string1 = "Windows_Antimalware_Host_System_Worker"
		$string2 = "Arkei"
		$string3 = "Bitcoin\\wallet.dat"
		$string4 = "Ethereum\\keystore"
		$v1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii wide
		$v2 = "/c taskkill /im " fullword ascii
		$v3 = "card_number_encrypted FROM credit_cards" ascii
		$v4 = "\\wallet.dat" ascii
		$v5 = "Arkei/" wide
		$v6 = "files\\passwords." ascii wide
		$v7 = "files\\cc_" ascii wide
		$v8 = "files\\autofill_" ascii wide
		$v9 = "files\\cookies_" ascii wide

	condition:
		uint16(0)==0x5A4D and ( all of ($string*) or 7 of ($v*))
}