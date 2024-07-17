rule ARKBIRD_SOLG_MAL_Pseudomanuscrypt_Dec_2021_1 : FILE
{
	meta:
		description = "Detect PseudoManuscrypt loader dropped by the installer"
		author = "Arkbird_SOLG"
		id = "8784baa0-c52c-5ee0-9a92-9b6457df61ed"
		date = "2021-12-16"
		modified = "2021-12-17"
		reference = "https://ics-cert.kaspersky.com/media/Kaspersky-ICS-CERT-PseudoManuscrypt-a-mass-scale-spyware-attack-campaign-En.pdf"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-12-16/MAL_PseudoManuscrypt_Dec_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "e304323ed26c7040c97efa8041bcd3eb2f6d0caeba76d6674fc2947d7850e830"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "19627bcee38a4ca5ae9a60c71ee7a2e388ba99fb8b229700a964a084db236e1f"
		hash2 = "be94df270acfc8e5470fa161b808d0de1c9e85efeeff4a5d82f5fd09629afa8e"
		hash3 = "de965e33dff58cf011106feacef2f804d9e35d00b8b5ff7064e5b7afee46d72c"
		hash4 = "e32899bef78f6af4a155f738298e042f72fe5e643ec934f8778180f71e511727"
		tlp = "white"
		adversary = "-"

	strings:
		$s1 = { 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 79 70 74 6f 67 72 61 70 68 79 00 7b 47 36 35 37 59 53 30 36 2d 30 31 36 44 2d 34 43 30 52 2d 36 30 32 32 2d 46 47 45 32 43 33 32 32 36 36 37 46 7d 00 00 4d 61 63 68 69 6e 65 47 75 69 64 }
		$s2 = { 45 ?? 5c 43 4c 53 c7 45 ?? 49 44 5c 25 c7 45 ?? 73 00 00 00 c7 45 ?? 47 6c 6f 62 c7 45 ?? 61 6c }
		$s3 = { 56 69 72 74 c7 [2-4] 75 61 6c 41 c7 [2-4] 6c 6c 6f 63 ff 15 }
		$s4 = { 4c 6f 61 64 65 72 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e }
		$s5 = { 2e 72 73 72 63 24 30 31 00 00 00 00 a0 ?? 00 00 ?? 04 00 00 2e 72 73 72 63 24 30 32 }

	condition:
		uint16(0)==0x5A4D and filesize >3KB and filesize <30KB and all of ($s*)
}