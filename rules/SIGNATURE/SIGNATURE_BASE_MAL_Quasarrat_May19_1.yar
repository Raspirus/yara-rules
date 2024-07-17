rule SIGNATURE_BASE_MAL_Quasarrat_May19_1 : FILE
{
	meta:
		description = "Detects QuasarRAT malware"
		author = "Florian Roth (Nextron Systems)"
		id = "a4e82b6a-31f8-59fc-acfa-805c4594680a"
		date = "2019-05-27"
		modified = "2023-01-06"
		reference = "https://blog.ensilo.com/uncovering-new-activity-by-apt10"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_quasar_rat.yar#L61-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a189bce433c71d45fd7f5d7fc284fc5b35c88a7ec616dd392d0e931165263aca"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0644e561225ab696a97ba9a77583dcaab4c26ef0379078c65f9ade684406eded"

	strings:
		$x1 = "Quasar.Common.Messages" ascii fullword
		$x2 = "Client.MimikatzTools" ascii fullword
		$x3 = "Resources.powerkatz_x86.dll" ascii fullword
		$x4 = "Uninstalling... good bye :-(" wide
		$xc1 = { 41 00 64 00 6D 00 69 00 6E 00 00 11 73 00 63 00
               68 00 74 00 61 00 73 00 6B 00 73 00 00 1B 2F 00
               63 00 72 00 65 00 61 00 74 00 65 00 20 00 2F 00
               74 00 6E 00 20 00 22 00 00 27 22 00 20 00 2F 00
               73 }
		$xc2 = { 00 70 00 69 00 6E 00 67 00 20 00 2D 00 6E 00 20
               00 31 00 30 00 20 00 6C 00 6F 00 63 00 61 00 6C
               00 68 00 6F 00 73 00 74 00 20 00 3E 00 20 00 6E
               00 75 00 6C 00 0D 00 0A 00 64 00 65 00 6C 00 20
               00 2F 00 61 00 20 00 2F 00 71 00 20 00 2F 00 66
               00 20 00 }

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and 1 of them
}