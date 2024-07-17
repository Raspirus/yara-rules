
rule TELEKOM_SECURITY_Win_Iceid_Core_Ldr_202104 : FILE
{
	meta:
		description = "2021 loader for Bokbot / Icedid core (license.dat)"
		author = "Thomas Barabosch, Telekom Security"
		id = "f096e18d-3a31-5236-b3c3-0df39b408d9a"
		date = "2021-04-13"
		modified = "2021-07-08"
		reference = "https://github.com/telekom-security/malware_analysis/"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/icedid/icedid_20210507.yar#L40-L62"
		license_url = "N/A"
		logic_hash = "d814dbaffb38dc71aaf373512246fd6d811750d526c4afffb0b8018329dcdd90"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$internal_name = "sadl_64.dll" fullword
		$string0 = "GetCommandLineA" fullword
		$string1 = "LoadLibraryA" fullword
		$string2 = "ProgramData" fullword
		$string3 = "SHLWAPI.dll" fullword
		$string4 = "SHGetFolderPathA" fullword
		$string5 = "DllRegisterServer" fullword
		$string6 = "update" fullword
		$string7 = "SHELL32.dll" fullword
		$string8 = "CreateThread" fullword

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ($internal_name and 5 of them ) or all of them
}