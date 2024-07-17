rule ARKBIRD_SOLG_MAL_Unknown_PE_Jul_2021_1 : FILE
{
	meta:
		description = "Detect unknown TA that focus russian people"
		author = "Arkbird_SOLG"
		id = "228e194c-84d9-562a-8811-326c5efeafae"
		date = "2020-07-14"
		modified = "2021-07-14"
		reference = "https://twitter.com/ShadowChasing1/status/1415292150258880513"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-14/MAL_Unknown_PE_Jul_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "9c61d2e29315bea0cdaf45b6dc48d35b8cc2d85de84afbb3a213f095a555af71"
		score = 75
		quality = 73
		tags = "FILE"
		hash1 = "ef80365cdbeb46fa208e98ca2f73b7d3d2bde10ea6c3f7cc22d4bbf39d921524"
		tlp = "white"
		adversary = "-"

	strings:
		$s1 = { 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 2f 00 53 00 43 00 20 00 4f 00 4e 00 43 00 45 00 20 00 2f 00 54 00 4e 00 20 00 25 00 73 00 20 00 2f 00 54 00 52 00 20 00 25 00 73 00 20 00 2f 00 52 00 49 00 20 00 31 00 20 00 2f 00 53 00 54 00 20 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 20 00 2f 00 45 00 54 00 20 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 20 00 2f 00 46 }
		$s2 = { 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 45 00 6e 00 64 00 20 00 2f 00 54 00 4e 00 20 00 25 00 73 }
		$s3 = { 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 2f 00 54 00 4e 00 20 00 25 00 73 00 20 00 2f 00 46 00 20 00 3c 00 20 00 25 00 73 }
		$s4 = "6ad5e187ae3e8911c420434551678df2.txt" fullword wide
		$s5 = { 55 52 4c 44 6f 77 6e 6c 6f 61 64 65 72 }
		$s6 = { 64 6c 6c 00 4d 79 45 78 70 6f 72 74 }

	condition:
		uint16(0)==0x5a4d and filesize >8KB and 5 of ($s*)
}