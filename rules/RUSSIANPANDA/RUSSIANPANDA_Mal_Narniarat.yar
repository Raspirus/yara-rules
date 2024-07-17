
rule RUSSIANPANDA_Mal_Narniarat : FILE
{
	meta:
		description = "Detects NarniaRAT from BotnetFenix campaign"
		author = "RussianPanda"
		id = "64c3a44b-5d75-5fec-bfc1-b66a5eb5780c"
		date = "2024-02-02"
		modified = "2024-02-02"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/NarniaRAT/mal_NarniaRAT.yar#L1-L16"
		license_url = "N/A"
		hash = "43f6c3f92a025d12de4c4f14afa5d098"
		logic_hash = "3ee8bf6b3970c6f56ca98c87752050217e350da160a650e1724b19f340bf0230"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "client-remote desktop"
		$s2 = "SendDataToServer"
		$s3 = "SendRunningApps"
		$s4 = "SendDataToServer"
		$s5 = "SendKeys"
		$s6 = "_CorExeMain"

	condition:
		uint16(0)==0x5A4D and 5 of them
}