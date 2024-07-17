rule ELASTIC_Windows_Trojan_Bloodalchemy_C2D80609 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bloodalchemy (Windows.Trojan.BloodAlchemy)"
		author = "Elastic Security"
		id = "c2d80609-9a66-4fbb-b594-17d16372cb14"
		date = "2023-09-25"
		modified = "2023-09-25"
		reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BloodAlchemy.yar#L63-L81"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "694a0f917f106fbdde4c8e5dd8f9cdce56e9423ce5a7c3a5bf30bf43308d42e9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8815e42ef85ae5a8915cd26b573cd7411c041778cdf4bc99efd45526e3699642"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 55 8B EC 83 EC 30 53 56 57 33 C0 8D 7D F0 AB 33 DB 68 02 80 00 00 6A 40 89 5D FC AB AB FF 15 28 }

	condition:
		all of them
}