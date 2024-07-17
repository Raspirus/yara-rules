rule ELASTIC_Windows_Hacktool_Phant0M_2D6F9B57 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Phant0M (Windows.Hacktool.Phant0m)"
		author = "Elastic Security"
		id = "2d6f9b57-bde0-4570-8e38-187dbf05e6d3"
		date = "2024-02-28"
		modified = "2024-03-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Phant0m.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "30978aadd7d7bc86e735facb5046942792ad1beab6919754e6765e0ccbcf89d6"
		logic_hash = "a66f8779f77b216f7831617a34c008e4202f36e74f2866c9792cee34b804408d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d4a92775e76bbb00e677a289942f9b3f8101a1dc2f55b30cfa32e4c7feae6c8a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$api = "NtQueryInformationThread"
		$s1 = "Suspending EventLog thread %d with start address %p"
		$s2 = "Found the EventLog Module (wevtsvc.dll) at %p"
		$s3 = "Event Log service PID detected as %d."
		$s4 = "Thread %d is detected and successfully killed."
		$s5 = "Windows EventLog module %S at %p"

	condition:
		$api and 2 of ($s*)
}