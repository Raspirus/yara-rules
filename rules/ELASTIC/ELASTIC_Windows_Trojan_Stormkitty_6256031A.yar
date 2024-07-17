rule ELASTIC_Windows_Trojan_Stormkitty_6256031A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Stormkitty (Windows.Trojan.StormKitty)"
		author = "Elastic Security"
		id = "6256031a-e7dd-423b-a83f-4db428cb3d1b"
		date = "2022-03-21"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_StormKitty.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0c69015f534d1da3770dbc14183474a643c4332de6a599278832abd2b15ba027"
		logic_hash = "a797e87eaf5b173da9dd43fcff03b3d26198dcafa29c3f2ca369773c73001234"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6f0463de42c97701b0f3b8172e7e461501357921a3d11e6ca467bd1ca397d0b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "https://github.com/LimerBoy/StormKitty" ascii fullword
		$a2 = "127.0.0.1 www.malwarebytes.com" wide fullword
		$a3 = "KillDefender"
		$a4 = "Username: {1}" wide fullword
		$a5 = "# End of Cookies" wide fullword
		$a6 = "# End of Passwords" wide fullword

	condition:
		all of them
}