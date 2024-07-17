
rule ELASTIC_Windows_Trojan_Fickerstealer_Cc02E75E : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Fickerstealer (Windows.Trojan.Fickerstealer)"
		author = "Elastic Security"
		id = "cc02e75e-2049-4ee4-9302-e491e7dad696"
		date = "2021-07-22"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Fickerstealer.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a4113ccb55e06e783b6cb213647614f039aa7dbb454baa338459ccf37897ebd6"
		logic_hash = "ccfd7edf7625c13eea5b88fa29f9b8d3d873688f328f3e52c0500ac722c84511"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "022088764645d85dd20d1ce201395b4e79e3e716723715687eaecfcbe667615e"
		severity = 80
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" ascii fullword
		$a2 = "\"SomeNone" ascii fullword

	condition:
		all of them
}