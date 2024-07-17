rule RUSSIANPANDA_Purelogs_Stealer_Initial_Dropper : FILE
{
	meta:
		description = "Detects PureLogs Stealer Initial Payload"
		author = "RussianPanda"
		id = "c1e6a0a0-f8ed-5b78-bcae-55c1c1dfc9e4"
		date = "2024-01-10"
		modified = "2024-01-10"
		reference = "https://russianpanda.com/2023/12/26/Pure-Logs-Stealer-Malware-Analysis/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Pure Logs Stealer/purelogs_stealer_initial_payload.yar#L1-L19"
		license_url = "N/A"
		logic_hash = "0fe94c705b94f82163f952d0a29aac4689947a1d439bdc1847ee510c25cf2e40"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {73 ?? 00 00 06 28 ?? 00 00 ?? 2A}
		$s2 = {28 ?? 00 00 06 74 ?? 00 00 1B 28 ?? 00 00 0A 2A}
		$s3 = {28 ?? 00 00 ?? 75 ?? 00 00 01 72 ?? 00 00 70 6F ?? 00 00 0A 2A}
		$s4 = {28 ?? 00 00 ?? 75 ?? 00 00 01 72 ?? 00 00 ?? 20 00 01 00 00 14 14 14 6F ?? 00 00 ?? 26}
		$s5 = {28 ?? 00 00 ?? 73 ?? 00 00 [29] 73 15 00 00 0A [22] 28 01 00 00 2B 28 02 00 00 2B}

	condition:
		all of ($s*) and uint16(0)==0x5A4D and filesize <1MB
}