rule RUSSIANPANDA_Solarmarker_First_Stage_Payload : FILE
{
	meta:
		description = "Detects SolarMarker First Stage payload"
		author = "RussianPanda"
		id = "56eec644-9ad7-51db-9d11-68ea3e12c36a"
		date = "2024-01-30"
		modified = "2024-01-30"
		reference = "https://x.com/luke92881/status/1751968350689771966?s=20"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/SolarMarker/solarmarker_first_stage_payload.yar#L1-L21"
		license_url = "N/A"
		hash = "f53563541293a826738d3b8f1164ea43"
		logic_hash = "e704614782b0f3cba60c53413e889113d2d44f37e60801205e5ed5ff921b13ee"
		score = 75
		quality = 71
		tags = "FILE"

	strings:
		$s1 = {63 72 65 64 75 69}
		$s2 = {43 72 65 64 55 49 50 72 6F 6D 70 74 46 6F 72 43 72 65 64 65 6E 74 69 61 6C 73}
		$s3 = {50 6F 77 65 72 53 68 65 6C 6C}
		$s4 = {73 65 74 5F 43 75 72 73 6F 72 50 6F 73 69 74 69 6F 6E}
		$s5 = {73 65 74 5F 41 63 63 65 70 74 42 75 74 74 6F 6E}
		$s6 = {4D 65 73 73 61 67 65 42 6F 78 42 75 74 74 6F 6E 73}
		$s7 = {41 67 69 6C 65 44 6F 74 4E 65 74 52 54}
		$s8 = "_CorExeMain"

	condition:
		all of them and filesize >250MB
}