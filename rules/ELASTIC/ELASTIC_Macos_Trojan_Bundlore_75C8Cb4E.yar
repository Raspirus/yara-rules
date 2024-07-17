
rule ELASTIC_Macos_Trojan_Bundlore_75C8Cb4E : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "75c8cb4e-f8bd-4a2c-8a5e-8500e12a9030"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3d69912e19758958e1ebdef5e12c70c705d7911c3b9df03348c5d02dd06ebe4e"
		logic_hash = "527fecb8460c0325c009beddd6992e0abbf8c5a05843e4cedf3b17deb4b19a1c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "db68c315dba62f81168579aead9c5827f7bf1df4a3c2e557b920fa8fbbd6f3c2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 EE 19 00 00 EA 80 35 E8 19 00 00 3B 80 35 E2 19 00 00 A4 80 35 DC 19 00 00 }

	condition:
		all of them
}