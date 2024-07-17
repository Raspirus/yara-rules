rule ARKBIRD_SOLG_Mal_Stealer_NET_Redline_Aug_2020_1 : FILE
{
	meta:
		description = "Detect Redline Stealer (August 2020)"
		author = "Arkbird_SOLG"
		id = "6fda87c3-0d00-5c00-a1ff-6d96dd726ddf"
		date = "2020-08-24"
		modified = "2020-08-24"
		reference = "https://twitter.com/JAMESWT_MHT/status/1297878628450152448"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-24/Redline/Mal_Stealer_NET_Redline_Aug_2020_1.yar#L1-L31"
		license_url = "N/A"
		logic_hash = "950641dfaf17f332e6a18961aebb2533732d82ce69f3617efa08cc63272f1786"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "4195430d95ac1ede9bc986728fc4211a1e000a9ba05a3e968dd302c36ab0aca0"

	strings:
		$s1 = { 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 57 00 68 00 65 00 72 00 65 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 49 00 64 00 3d 00 27 00 7b 00 30 00 7d }
		$s2 = { 28 00 28 00 28 00 28 00 5b 00 30 00 2d 00 39 00 2e 00 5d 00 29 00 5c 00 64 00 29 00 2b 00 29 00 7b 00 31 00 7d 00 29 }
		$s3 = { 7b 00 30 00 7d 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c }
		$s4 = { 7b 00 30 00 7d 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 73 00 69 00 74 00 65 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 78 00 6d 00 6c }
		$s5 = { 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 61 00 72 00 74 00 69 00 6e 00 20 00 50 00 72 00 69 00 6b 00 72 00 79 00 6c 00 5c 00 57 00 69 00 6e 00 53 00 43 00 50 00 20 00 32 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 73 }
		$s6 = "<encrypted_key>k__BackingField" fullword ascii
		$s7 = "set_encrypted_key" fullword ascii
		$s8 = "UserAgentDetector" fullword ascii
		$s9 = "set_encrypted_key" fullword ascii
		$s10 = "set_FtpConnections" fullword ascii
		$s11 = "set_IsProcessElevated" fullword ascii
		$s12 = "SELECT ExecutablePath, ProcessID FROM Win32_Process" fullword wide
		$s13 = "<IsProcessElevated>k__BackingField" fullword ascii
		$s14 = "System.Collections.Generic.IEnumerable<RedLine.Logic.Json.JsonValue>.GetEnumerator" fullword ascii
		$s15 = "System.Collections.Generic.IEnumerator<RedLine.Logic.Json.JsonValue>.get_Current" fullword ascii
		$s16 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\browser.exe" fullword wide
		$s17 = "ProcessExecutablePath" fullword ascii
		$s18 = "IsProcessElevated" fullword ascii
		$s19 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe" fullword wide
		$s20 = "get_encryptedPassword" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <90KB and 15 of them
}