
rule ELASTIC_Windows_Trojan_Raccoon_Deb6325C : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Raccoon (Windows.Trojan.Raccoon)"
		author = "Elastic Security"
		id = "deb6325c-5556-44ce-a184-6369105485d5"
		date = "2022-06-28"
		modified = "2022-07-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Raccoon.yar#L42-L63"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f7b1aaae018d5287444990606fc43a0f2deb4ac0c7b2712cc28331781d43ae27"
		logic_hash = "94f70c60ed4fab021e013cf6a632321e0e1bdeef25a48a598d9e7388e7e445ca"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "17c34b5b9a0211255a93f9662857361680e72a45135d6ea9b5af8d77b54583b9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\ffcookies.txt" wide fullword
		$a2 = "wallet.dat" wide fullword
		$a3 = "0Network\\Cookies" wide fullword
		$a4 = "Wn0nlDEXjIzjLlkEHYxNvTAXHXRteWg0ieGKVyD52CvONbW7G91RvQDwSZi/N2ISm4xEWRKYJwjnYUGS9OZmj/TAie8jG07EXEcO8D7h2m2lGzWnFG31R1rsxG1+G8E="

	condition:
		all of them
}