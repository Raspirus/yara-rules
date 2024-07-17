rule ELASTIC_Windows_Trojan_Metasploit_B29Fe355 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Metasploit (Windows.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "b29fe355-b7f8-4325-bf06-7975585f3888"
		date = "2022-06-08"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L248-L268"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4f0ab4e42e6c10bc9e4a699d8d8819b04c17ed1917047f770dc6980a0a378a68"
		logic_hash = "7a2189b59175acb66a7497c692a43c413a476f5c4371f797bf03a8ddb550992c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a943325b7a227577ccd45748b4e705288c5b7d91d0e0b2a115daeea40e1a2148"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%04x-%04x:%s" fullword
		$a2 = "\\\\%s\\pipe\\%s" fullword
		$a3 = "PACKET TRANSMIT" fullword

	condition:
		all of them
}