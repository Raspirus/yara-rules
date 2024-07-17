
rule SIGNATURE_BASE_SUSP_PS1_Msdt_Execution_May22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190 / Follina exploitation"
		author = "Nasreddine Bencherchali, Christian Burkard"
		id = "caa8a042-ffd4-52b2-a9f0-86e6c83a0aa3"
		date = "2022-05-31"
		modified = "2022-07-08"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L1-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "72ab851eecece30e11e2158da94267c64c187be400926ba6bbcbdc59d0a349dc"
		score = 75
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$a = "PCWDiagnostic" ascii wide fullword
		$sa1 = "msdt.exe" ascii wide
		$sa2 = "msdt " ascii wide
		$sa3 = "ms-msdt" ascii wide
		$sb1 = "/af " ascii wide
		$sb2 = "-af " ascii wide
		$sb3 = "IT_BrowseForFile=" ascii wide
		$fp1 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00
               46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00
               00 00 70 00 63 00 77 00 72 00 75 00 6E 00 2E 00
               65 00 78 00 65 00 }
		$fp2 = "FilesFullTrust" wide

	condition:
		filesize <10MB and $a and 1 of ($sa*) and 1 of ($sb*) and not 1 of ($fp*)
}