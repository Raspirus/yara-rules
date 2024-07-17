
rule ARKBIRD_SOLG_APT_Evilnum_LNK_Jul_2021_1 : FILE
{
	meta:
		description = "Detect LNK file used by EvilNum group"
		author = "Arkbird_SOLG"
		id = "9d570c02-606a-5bff-af7a-9b5ef1e6df90"
		date = "2020-07-13"
		modified = "2021-07-14"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-13/EvilNum/APT_EvilNum_LNK_Jul_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "d20aadfce6a0246f415f94a62edbf7fd48dcdcd9756a5a8d898a5459633b9350"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "b60ae30ba90f852f886bb4e9aaabe910add2b70278e3a88a3b7968f644e10554"
		hash2 = "bc203f44b48c9136786891be153311c37ce74ceb7eb540d515032c152f5eb2fb"
		hash3 = "fefc9dbb46bc02a2bdccbf3c581d270f6341562e050e5357484ecae7e1e702f3"
		tlp = "white"
		adversary = "EvilNum"

	strings:
		$s1 = "1-5-21-669817101-1001941732-3035937113-1000" fullword wide
		$s2 = "*..\\..\\..\\..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide
		$s3 = "C:\\Windows\\System32\\cmd.exe" fullword wide
		$s4 = "System32 (C:\\Windows)" fullword wide
		$s5 = { 3d 00 25 00 74 00 6d 00 70 00 25 00 5c 00 74 00 65 00 73 00 74 00 2e 00 63 00 26 }
		$s6 = { 3c 00 22 00 25 [5] 25 00 6d 00 64 00 22 00 26 00 6e 00 65 00 74 00 73 00 74 00 61 00 74 00 20 00 2d }
		$s7 = { 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 41 00 63 00 63 00 65 00 73 00 73 00 6f 00 72 00 69 00 65 00 73 00 5c 00 77 00 6f 00 72 00 64 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 }

	condition:
		filesize >60KB and 6 of ($s*)
}