
rule ELASTIC_Windows_Trojan_Siestagraph_Ad3Fe5C6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Siestagraph (Windows.Trojan.SiestaGraph)"
		author = "Elastic Security"
		id = "ad3fe5c6-88ba-46cf-aefd-bd8ab0eff917"
		date = "2023-09-12"
		modified = "2023-09-20"
		reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SiestaGraph.yar#L30-L56"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fe8f99445ad139160a47b109a8f3291eef9c6a23b4869c48d341380d608ed4cb"
		logic_hash = "b625221b77803c2c052db09c90a76666cf9e0ae34cb0d59ae303e890e646e94b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "653ca92d31c7212c1f154c2e18b3be095e9a39fe482ce99fbd84e19f4bf6ca64"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "GetAllDriveRootChildren" ascii fullword
		$a2 = "GetDriveRoot" ascii fullword
		$a3 = "sendsession" wide fullword
		$b1 = "status OK" wide fullword
		$b2 = "upload failed" wide fullword
		$b3 = "Failed to fetch file" wide fullword
		$c1 = "Specified file doesn't exist" wide fullword
		$c2 = "file does not exist" wide fullword

	condition:
		6 of them
}