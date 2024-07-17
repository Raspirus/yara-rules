
rule CAPE_Ryuk : FILE
{
	meta:
		description = "Ryuk Payload"
		author = "kevoreilly"
		id = "594bbb8d-1f85-5a01-a864-ac2d95c45bf9"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Ryuk.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "b4463993d8956e402b927a3dcfa2ca9693a959908187f720372f2d3a40e6db0c"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Ryuk Payload"

	strings:
		$ext = ".RYK" wide
		$readme = "RyukReadMe.txt" wide
		$main = "InvokeMainViaCRT"
		$code = {48 8B 4D 10 48 8B 03 48 C1 E8 07 C1 E0 04 F7 D0 33 41 08 83 E0 10 31 41 08 48 8B 4D 10 48 8B 03 48 C1 E8 09 C1 E0 03 F7 D0 33 41 08 83 E0 08 31 41 08}

	condition:
		uint16(0)==0x5A4D and 3 of ($*)
}