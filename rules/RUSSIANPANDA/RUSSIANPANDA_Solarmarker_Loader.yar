rule RUSSIANPANDA_Solarmarker_Loader : FILE
{
	meta:
		description = "Detects SolarMarker loader 1-4-2024"
		author = "RussianPanda"
		id = "b385fcd4-62b7-5a83-8a2e-6841fdd17526"
		date = "2024-01-04"
		modified = "2024-01-04"
		reference = "https://www.esentire.com/blog/solarmarker-to-jupyter-and-back"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/SolarMarker/solarmarker_backdoor.yar#L3-L19"
		license_url = "N/A"
		hash = "8eeefe0df0b057fc866b8d35625156de"
		logic_hash = "035eccb41f2ecdeb196003542c165cedad96e3e8e741511b4beda3dfe1ece74e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {06 [0-7] 58 D1 8C [3] 01 28 [3] 0A 0A}

	condition:
		all of ($s*) and #s1>5 and filesize <7MB and pe.imports("mscoree.dll")
}