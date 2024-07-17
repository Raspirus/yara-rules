import "pe"


rule RUSSIANPANDA_Ducktail_Mainbot : FILE
{
	meta:
		description = "Detects Ducktail mainbot"
		author = "RussianPanda"
		id = "f280903f-13d3-54e1-8308-781e3f777d13"
		date = "2023-12-24"
		modified = "2023-12-26"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Ducktail/ducktail_mainbot-12-2023.yar#L3-L19"
		license_url = "N/A"
		logic_hash = "33b85c6e1e1137aeeb07eba957b73d738a70ddc561b42bd2d39258e90280fca4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {2F 00 61 00 70 00 69 00 2F 00 63 00 68 00 65 00 63 00 6B}
		$s2 = {62 00 65 00 67 00 69 00 6E 00 20 00 63 00 6F 00 6E 00 6E 00 65 00 63 00 74}
		$s3 = {62 00 65 00 67 00 69 00 6E 00 20 00 66 00 6C 00 75 00 73 00 68 00 20 00 64 00 6E 00 73}
		$s4 = {62 00 65 00 67 00 69 00 6E 00 20 00 73 00 65 00 6E 00 64 00 69 00 6E 00 67}

	condition:
		all of ($s*) and filesize <12MB and pe.exports("DotNetRuntimeDebugHeader")
}