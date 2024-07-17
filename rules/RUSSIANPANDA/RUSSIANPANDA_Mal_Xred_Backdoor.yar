rule RUSSIANPANDA_Mal_Xred_Backdoor : FILE
{
	meta:
		description = "Detects XRed backdoor"
		author = "RussianPanda"
		id = "61f5fcb8-9351-5db0-8bce-123c96d2a443"
		date = "2024-02-09"
		modified = "2024-02-09"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/XRed_Backdoor/mal_xred_backdoor.yar#L1-L18"
		license_url = "N/A"
		hash = "9e1fbae3a659899dde8db18a32daa46a"
		logic_hash = "36d138a0efade1d5c075662dc528235fe66b49879730db78c4c7290fec7420b5"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$s1 = {4B 65 79 62 6F 61 72 64 20 48 6F 6F 6B 20 2D 3E 20 41 63 74 69 76 65}
		$s2 = {54 43 50 20 43 6C 69 65 6E 74 20 2D 3E 20 41 6B 74 69 66}
		$s3 = {55 53 42 20 48 6F 6F 6B 73 20 2D 3E 20 41 63 74 69 76 65}
		$s4 = {45 58 45 55 52 4C 31}
		$s5 = {49 4E 49 55 52 4C 33}
		$s6 = {58 52 65 64 35 37}

	condition:
		uint16(0)==0x5A4D and 3 of them
}