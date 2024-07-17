rule RUSSIANPANDA_Ducktail : FILE
{
	meta:
		description = "Ducktail Infostealer"
		author = "RussianPanda"
		id = "14ba165f-a1f3-5820-a6d8-e2b6ab2fbb51"
		date = "2023-04-25"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Ducktail/ducktail.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "cb248870f6945d7a6d60d54944dc726d40ba326448af39b87325ec56445602a5"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$s = {65 5f 73 71 6c 69 74 65 33 2e 64 6c 6c}
		$s1 = {54 65 6c 65 67 72 61 6d 2e 42 6f 74 2e 64 6c 6c}
		$s2 = {4e 65 77 74 6f 6e 73 6f 66 74 2e 4a 73 6f 6e 2e 64 6c 6c}
		$s3 = {42 6f 75 6e 63 79 43 61 73 74 6c 65 2e 43 72 79 70 74 6f 2e 64 6c 6c}
		$s4 = {53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 53 6f 63 6b 65 74 73 2e 43 6c 69 65 6e 74 2e 64 6c 6c}
		$s5 = {53 79 73 74 65 6d 2e 4e 65 74 2e 4d 61 69 6c 2e 64 6c 6c}

	condition:
		all of them and filesize >60MB
}