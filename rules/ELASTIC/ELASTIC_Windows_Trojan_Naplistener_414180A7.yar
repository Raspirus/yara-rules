
rule ELASTIC_Windows_Trojan_Naplistener_414180A7 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Naplistener (Windows.Trojan.NapListener)"
		author = "Elastic Security"
		id = "414180a7-ca8d-4cf8-a346-08c3e0e1ed8a"
		date = "2023-02-28"
		modified = "2023-03-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_NapListener.yar#L23-L46"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6e8c5bb2dfc90bca380c6f42af7458c8b8af40b7be95fab91e7c67b0dee664c4"
		logic_hash = "52d3ddebdc1a8aa4bcb902273bd2d3b4f9b51f248d25e7ae1cc260a9550111f5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "460b21638f200bf909e9e47bc716acfcb323540fbaa9ea9d0196361696ffa294"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "https://*:443/ews/MsExgHealthCheckd/" ascii wide
		$a2 = "FillFromEncodedBytes" ascii wide
		$a3 = "Exception caught" ascii wide
		$a4 = "text/html; charset=utf-8" ascii wide
		$a5 = ".Run" ascii wide
		$a6 = "sdafwe3rwe23" ascii wide

	condition:
		5 of them
}