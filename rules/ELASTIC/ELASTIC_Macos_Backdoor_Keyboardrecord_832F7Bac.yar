rule ELASTIC_Macos_Backdoor_Keyboardrecord_832F7Bac : FILE
{
	meta:
		description = "Detects Macos Backdoor Keyboardrecord (MacOS.Backdoor.Keyboardrecord)"
		author = "Elastic Security"
		id = "832f7bac-3896-4934-b05f-8215a41cca74"
		date = "2021-11-11"
		modified = "2022-07-22"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Backdoor_Keyboardrecord.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "570cd76bf49cf52e0cb347a68bdcf0590b2eaece134e1b1eba7e8d66261bdbe6"
		logic_hash = "5719681d50134edacb5341034314c33ed27e9325de0ae26b2a01d350429c533b"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "27aa4380bda0335c672e957ba2ce6fd1f42ccf0acd2eff757e30210c3b4fb2fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$s1 = "com.ccc.keyboardrecord"
		$s2 = "com.ccc.write_queue"
		$s3 = "ps -p %s > /dev/null"
		$s4 = "useage %s path useragentpid"
		$s5 = "keyboardRecorderStartPKc"

	condition:
		3 of them
}