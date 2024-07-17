rule ELASTIC_Linux_Trojan_Generic_Be1757Ef : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "be1757ef-cf45-4c00-8d6c-dbb0f44f6efb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e4e2b5af9d0c72aae83cec57e5c091a95c549f826e8f13559aaf7d300f6e13"
		logic_hash = "567d33c262e5f812c6a702bcc0a1f0cf576b67bf7cf67bb82b5f9ce9f233aaff"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "0af6b01197b63259d9ecbc24f95b183abe7c60e3bf37ca6ac1b9bc25696aae77"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 54 68 75 20 4D 61 72 20 31 20 31 34 3A 34 34 3A 30 38 20 }

	condition:
		all of them
}