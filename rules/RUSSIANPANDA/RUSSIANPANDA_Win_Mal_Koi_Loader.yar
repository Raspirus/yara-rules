rule RUSSIANPANDA_Win_Mal_Koi_Loader : FILE
{
	meta:
		description = "Detects Koi Loader"
		author = "RussianPanda"
		id = "a608558d-97c8-5161-a6eb-29fd420458a8"
		date = "2024-04-04"
		modified = "2024-04-04"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Koi/win_mal_Koi_loader.yar#L1-L14"
		license_url = "N/A"
		hash = "47e208687c2fb40bdbaa17e368aaa1bd"
		logic_hash = "4f909865c6d274804c3fa7f66822d7bea71bb93e7c6a422ebaf220df056ac095"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {27 11 68 05}
		$s2 = {15 B1 B3 09}
		$s3 = {B5 96 AA 0D}
		$s4 = {74 [0-10] C1 E9 18}

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}