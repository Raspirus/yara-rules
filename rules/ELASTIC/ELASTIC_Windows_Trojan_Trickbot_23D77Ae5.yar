
rule ELASTIC_Windows_Trojan_Trickbot_23D77Ae5 : FILE MEMORY
{
	meta:
		description = "Targets importDll64 containing Browser data stealer module"
		author = "Elastic Security"
		id = "23d77ae5-80de-4bb0-8701-ddcaff443dcc"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L364-L396"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "844974a2d3266e1f9ba275520c0e8a5d176df69a0ccd5135b99facf798a5d209"
		logic_hash = "e5f5cf854ebd0e25fffbd6796217f22223a06937e1cacb33baa105ac41731256"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d382a99e5eed87cf2eab5e238e445ca0bf7852e40b0dd06a392057e76144699f"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "/system32/cmd.exe /c \"start microsoft-edge:{URL}\"" ascii fullword
		$a2 = "SELECT name, value, host_key, path, expires_utc, creation_utc, encrypted_value FROM cookies" ascii fullword
		$a3 = "attempt %d. Cookies not found" ascii fullword
		$a4 = "attempt %d. History not found" ascii fullword
		$a5 = "Cookies version is %d (%d)" ascii fullword
		$a6 = "attempt %d. Local Storage not found" ascii fullword
		$a7 = "str+='xie.com.'+p+'.guid='+'{'+components[i]+'}\\n';" ascii fullword
		$a8 = "Browser exec is: %s" ascii fullword
		$a9 = "found mozilla key: %s" ascii fullword
		$a10 = "Version %d is not supported" ascii fullword
		$a11 = "id %d - %s" ascii fullword
		$a12 = "prot: %s, scope: %s, port: %d" ascii fullword
		$a13 = "***** Send %d bytes to callback from %s *****" ascii fullword
		$a14 = "/chrome.exe {URL}" ascii fullword

	condition:
		4 of ($a*)
}