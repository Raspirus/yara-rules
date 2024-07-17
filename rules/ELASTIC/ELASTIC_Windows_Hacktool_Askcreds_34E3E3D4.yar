
rule ELASTIC_Windows_Hacktool_Askcreds_34E3E3D4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Askcreds (Windows.Hacktool.AskCreds)"
		author = "Elastic Security"
		id = "34e3e3d4-7516-4e0e-b3e7-5bc84404bd08"
		date = "2023-05-16"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_AskCreds.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d911566ca546a8546928cd0ffa838fd344b35f75a4a7e80789d20e52c7cd38d0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e00dd2496045d1b71119b35c30c4c010c0ad57f67691649c0f4d206f837bd05d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Failed to create AskCreds thread."
		$a2 = "CredUIPromptForWindowsCredentialsW failed"
		$a3 = "[+] Password: %ls"

	condition:
		2 of them
}