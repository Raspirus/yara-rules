rule RUSSIANPANDA_Mal_Botnetfenix_Payload : FILE
{
	meta:
		description = "Detects BotnetFenix payload"
		author = "RussianPanda"
		id = "566bfae1-c43d-5bd6-adcf-faff32d8c325"
		date = "2024-02-02"
		modified = "2024-02-04"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/FenixBotnet/mal_BotnetFenix_Payload.yar#L1-L16"
		license_url = "N/A"
		hash = "65a9575c50a96d04a3f649fe0f6b8ccd"
		logic_hash = "27f423b509ad8de0f8389c7b3e3bfec2eeb10c964aa8c70bad47cc4334df1a5e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "tasks_register"
		$s2 = "actionget_action"
		$s3 = "Post Success"
		$s4 = "Success Stealer"
		$s5 = "Download and Execute task id"
		$a = "_CorExeMain"

	condition:
		uint16(0)==0x5A4D and 4 of ($s*) and $a
}