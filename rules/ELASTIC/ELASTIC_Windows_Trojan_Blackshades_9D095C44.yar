rule ELASTIC_Windows_Trojan_Blackshades_9D095C44 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Blackshades (Windows.Trojan.BlackShades)"
		author = "Elastic Security"
		id = "9d095c44-5047-453e-8435-f30de94565e6"
		date = "2022-02-28"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BlackShades.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e58e352edaa8ae7f95ab840c53fcaf7f14eb640df9223475304788533713c722"
		logic_hash = "2a2e6325d3de9289cc8bc26e1fe89a8fa81d9aae50b92ba2cf21c4cc6556ac9e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "be7d4c8200c293c3c8046d9f87b0d127ff051679ae1caeab12c533ea4309a1fc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
		$a2 = "@*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
		$a3 = "D:\\Blackshades Project\\bs_net\\loginserver\\msvbvm60.dll\\3" ascii fullword
		$b1 = "modSniff" ascii fullword
		$b2 = "UDPFlood" ascii fullword
		$b3 = "\\nir_cmd.bss speak text " wide fullword
		$b4 = "\\pws_chro.bss" wide fullword
		$b5 = "tmrLiveLogger" ascii fullword

	condition:
		1 of ($a*) or all of ($b*)
}