
rule ELASTIC_Windows_Trojan_Siestagraph_8C36Ddc1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Siestagraph (Windows.Trojan.SiestaGraph)"
		author = "Elastic Security"
		id = "8c36ddc1-c7fa-4c25-a05c-59c29e4e7c31"
		date = "2022-12-14"
		modified = "2022-12-15"
		reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SiestaGraph.yar#L1-L28"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "50c2f1bb99d742d8ae0ad7c049362b0e62d2d219b610dcf25ba50c303ccfef54"
		logic_hash = "17ce8090b88100f00c07df0599cd51dc7682f4c43de989ce58621df97eca42fb"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "a76d2b45261da65215797a4792a3aae5051d88ba15d01b24487c83d6a38b9ff7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "downloadAsync" ascii nocase fullword
		$a2 = "UploadxAsync" ascii nocase fullword
		$a3 = "GetAllDriveRootChildren" ascii fullword
		$a4 = "GetDriveRoot" ascii fullword
		$a5 = "sendsession" wide fullword
		$b1 = "ListDrives" wide fullword
		$b2 = "Del OK" wide fullword
		$b3 = "createEmailDraft" ascii fullword
		$b4 = "delMail" ascii fullword

	condition:
		all of ($a*) and 2 of ($b*)
}