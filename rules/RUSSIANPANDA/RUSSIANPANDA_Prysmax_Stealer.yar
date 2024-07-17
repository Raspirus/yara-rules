rule RUSSIANPANDA_Prysmax_Stealer : FILE
{
	meta:
		description = "Detects Prysmax Stealer"
		author = "RussianPanda"
		id = "97ab92b8-1771-5881-9cd1-d8ff76b8f380"
		date = "2024-01-09"
		modified = "2024-01-10"
		reference = "https://www.cyfirma.com/outofband/new-maas-prysmax-launches-fully-undetectable-infostealer/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Prysmax Stealer/prysmax_stealer.yar#L1-L21"
		license_url = "N/A"
		logic_hash = "869eee7dd5209bdea98c248791b9ac911e3daabe6d440aa62aecefa43539a41c"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$a1 = {23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23}
		$s2 = {73 70 72 79 73 6D 61 78}
		$s3 = {56 43 52 55 4E 54 49 4D 45 31 34 30 2E 64 6C 6C}
		$s4 = {56 43 52 55 4E 54 49 4D 45 31 34 30 5F 31 2E 64 6C 6C}
		$s5 = {4D 53 56 43 50 31 34 30 2E 64 6C 6C}
		$s6 = {50 79 49 6E 73 74 61 6C 6C 65 72}

	condition:
		all of ($s*) and uint16(0)==0x5A4D and $a1 in (9600000.. filesize ) and #a1>600 and filesize >60MB and filesize <200MB
}