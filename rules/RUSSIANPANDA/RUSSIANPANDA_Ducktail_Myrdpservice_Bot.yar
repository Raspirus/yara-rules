import "pe"


rule RUSSIANPANDA_Ducktail_Myrdpservice_Bot : FILE
{
	meta:
		description = "Detects Ducktail myRdpService bot"
		author = "RussianPanda"
		id = "50786786-a7db-5290-a363-6fda139a0343"
		date = "2023-12-24"
		modified = "2023-12-26"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Ducktail/ducktail_myrdpservice-12-2023.yar#L3-L17"
		license_url = "N/A"
		logic_hash = "a329067fbb2acc34c4970167bbce0706c5a3ec09ee89ce16817c105ae1c17b1b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {43 00 3A 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 54 00 65 00 6D 00 70 00 5C 00 64 00 65 00 76 00 69 00 63 00 65 00 49 00 64 00 2E 00 74 00 78 00 74}
		$s2 = {6C 00 6F 00 67 00 5F 00 72 00 64 00 70 00 2A}
		$s3 = {00 43 00 6F 00 6E 00 6E 00 65 00 63 00 74 00 65 00 64 00}

	condition:
		all of ($s*) and filesize <12MB and pe.exports("DotNetRuntimeDebugHeader")
}