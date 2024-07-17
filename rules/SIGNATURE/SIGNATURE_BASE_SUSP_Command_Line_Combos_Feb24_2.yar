rule SIGNATURE_BASE_SUSP_Command_Line_Combos_Feb24_2 : SCRIPT FILE
{
	meta:
		description = "Detects suspicious command line combinations often found in post exploitation activities"
		author = "Florian Roth"
		id = "d9bc6083-c3ca-5639-a9df-483fea6d0187"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L105-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0cd7b4771aa8fd622e873c5cdc6689d24394e5faf026b36d5f228ac09f4e0441"
		score = 75
		quality = 85
		tags = "SCRIPT, FILE"

	strings:
		$sa1 = " | iex"
		$sa2 = "iwr -UseBasicParsing "

	condition:
		filesize <2MB and all of them
}