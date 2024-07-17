
rule RUSSIANPANDA_Solarmarker_Loader_PS2EXE : FILE
{
	meta:
		description = "Detects SolarMarker loader using PS2EXE"
		author = "RussianPanda"
		id = "837883a1-b657-52ae-95c4-ebafc8ac55de"
		date = "2024-01-04"
		modified = "2024-01-04"
		reference = "https://www.esentire.com/blog/solarmarker-to-jupyter-and-back"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/SolarMarker/solarmarker_loader.yar#L1-L17"
		license_url = "N/A"
		hash = "b45c31679c2516b38c7ff8c395f1d11d"
		logic_hash = "4f579f350c3320e7b811cae0efe7302e852f59adc02d805f64ba464f8a995f25"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {72 7B 02 00 70 72 89 02 00 70 72 91 02 00 70 [22] 72 97 02 00 70 72 AB 02 00 70 72 B5 02 00 70}
		$s2 = {13 0D 72 [3] 70}
		$s3 = {72 C1 02 00 70 72 B2 03 00 70 72 B8 03 00 70}

	condition:
		all of ($s*) and filesize >200MB
}