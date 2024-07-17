rule ELASTIC_Windows_Ransomware_Blackbasta_494D3C54 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Blackbasta (Windows.Ransomware.BlackBasta)"
		author = "Elastic Security"
		id = "494d3c54-4690-4334-b64d-ebeeb305de0e"
		date = "2022-08-06"
		modified = "2022-08-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_BlackBasta.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "357fe8c56e246ffacd54d12f4deb9f1adb25cb772b5cd2436246da3f2d01c222"
		logic_hash = "1ecb3c95a2d3f91d267f0b625fffc8477612fde9de3942eff8eb13115c0af6b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "27602cb05c054a1aa9e27b91675d57707f4a63fa91badc83ad86229839778f4e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii fullword
		$a2 = "Creating readme at %s" wide fullword
		$a3 = "All of your files are currently encrypted by no_name_software." ascii fullword
		$a4 = "DON'T move or rename your files. These parameters can be used for encryption/decryption process." ascii fullword
		$b1 = "Your data are stolen and encrypted" ascii fullword
		$b2 = "bcdedit /deletevalue safeboot" ascii fullword
		$b3 = "Your company id for log in:"
		$byte_seq = { 0F AF 45 DC 8B CB 0F AF 4D DC 0F AF 5D D8 0F AF 55 D8 8B F9 }
		$byte_seq2 = { 18 FF 24 1E 18 FF 64 61 5D FF CF CF CF FF D0 D0 D0 FF D0 D0 D0 FF }

	condition:
		4 of them
}