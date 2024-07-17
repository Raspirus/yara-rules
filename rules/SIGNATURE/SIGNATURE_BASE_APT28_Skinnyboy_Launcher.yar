rule SIGNATURE_BASE_APT28_Skinnyboy_Launcher : RUSSIA FILE
{
	meta:
		description = "Detects APT28 SkinnyBoy launchers"
		author = "Cluster25"
		id = "eaf4e8e5-cbec-5000-a2ff-31d1dac4c30f"
		date = "2021-05-24"
		modified = "2023-12-05"
		reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt28.yar#L120-L141"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cbb7a6e0114a9556a99ab3f5601664f430b650b2de0b44fe0178a99f21082e8d"
		score = 75
		quality = 85
		tags = "RUSSIA, FILE"
		hash1 = "2a652721243f29e82bdf57b565208c59937bbb6af4ab51e7b6ba7ed270ea6bce"

	strings:
		$sha = {F4 EB 56 52 AF 4B 48 EE 08 FF 9D 44 89 4B D5 66 24 61 2A 15 1D 58 14 F9 6D 97
      13 2C 6D 07 6F 86}
		$l1 = "CryptGetHashParam" ascii
		$l2 = "CryptCreateHash" ascii
		$l3 = "FindNextFile" ascii
		$l4 = "PathAddBackslashW" ascii
		$l5 = "PathRemoveFileSpecW" ascii
		$h1 = {50 6A 00 6A 00 68 0C 80 00 00 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A 00
      56 ?? ?? ?? ?? 50 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ??}
		$h2 = {8B 01 3B 02 75 10 83 C1 04 83 C2 04 83 EE 04 73 EF}

	condition:
		uint16(0)==0x5a4d and filesize <100KB and ($sha or ( all of ($l*) and all of ($h*)))
}