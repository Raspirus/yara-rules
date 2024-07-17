rule ELASTIC_Macos_Trojan_Metasploit_448Fa81D : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Metasploit (MacOS.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "448fa81d-14c7-479b-8d1e-c245ee261ef6"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L44-L64"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
		logic_hash = "ab0608920b9f632bad99e1358f21a88bc6048f46fca21a488a1a10b7ef1e42ae"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ff040211f664f3f35cd4f4da0e5eb607ae3e490aae75ee97a8fb3cb0b08ecc1f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = "/Users/vagrant/mettle/mettle/src/process.c" ascii fullword
		$a2 = "/Users/vagrant/mettle/mettle/src/c2_http.c" ascii fullword
		$a3 = "/Users/vagrant/mettle/mettle/src/mettle.c" ascii fullword

	condition:
		any of them
}