
rule ELASTIC_Windows_Trojan_Microbackdoor_46F2E5Fd : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Microbackdoor (Windows.Trojan.MicroBackdoor)"
		author = "Elastic Security"
		id = "46f2e5fd-edea-4321-b38c-7478b47f054b"
		date = "2022-03-07"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_MicroBackdoor.yar#L21-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fbbfcc81a976b57739ef13c1545ea4409a1c69720469c05ba249a42d532f9c21"
		logic_hash = "580be4c5b058916c2bc67a7964522a7c369bb254394e3cedbf0da025105231c4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d4e410b9c36c1d5206f5d17190ef4e5fd4b4e4d40acad703775aed085a08ef7c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "cmd.exe /C \"%s%s\"" wide fullword
		$a2 = "%s|%s|%d|%s|%d|%d" wide fullword
		$a3 = "{{{$%.8x}}}" ascii fullword
		$a4 = "30D78F9B-C56E-472C-8A29-E9F27FD8C985" ascii fullword
		$a5 = "chcp 65001 > NUL & " wide fullword
		$a6 = "CONNECT %s:%d HTTP/1.0" ascii fullword

	condition:
		5 of them
}