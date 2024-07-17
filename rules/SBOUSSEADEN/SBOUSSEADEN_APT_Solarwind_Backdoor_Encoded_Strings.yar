
rule SBOUSSEADEN_APT_Solarwind_Backdoor_Encoded_Strings : FILE
{
	meta:
		description = "This rule is looking for some key encoded strings of the SUNBURST backdoor"
		author = "SBousseaden"
		id = "04a63bd6-9737-568f-a20e-c573b915cbd4"
		date = "2020-12-14"
		modified = "2020-12-18"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/apt_solarwinds_backdoor_encoded_strings.yara#L1-L28"
		license_url = "N/A"
		hash = "846e27a652a5e1bfbd0ddd38a16dc865"
		logic_hash = "8808cca8d89f089a8bca5ef62c1764061c8210ba5f9813c886d6ed9f79579ba6"
		score = 75
		quality = 75
		tags = "FILE"
		sha2 = "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"

	strings:
		$sw = "SolarWinds"
		$priv1 = "C04NScxO9S/PSy0qzsgsCCjKLMvMSU1PBQA=" wide
		$priv2 = "C04NzigtSckvzwsoyizLzElNTwUA" wide
		$priv3 = "C04NSi0uyS9KDSjKLMvMSU1PBQA=" wide
		$disc1 = "C0gsSs0rCSjKT04tLvZ0AQA=" wide
		$disc2 = "c0zJzczLLC4pSizJLwIA" wide
		$disc3 = "c/ELdsnPTczMCy5NS8usCE5NLErO8C9KSS0CAA==" wide
		$wmi1 = "C07NSU0uUdBScCvKz1UIz8wzNooPriwuSc11KcosSy0CAA==" wide
		$wmi2 = "C07NSU0uUdBScCvKz1UIz8wzNooPKMpPTi0uBgA=" wide
		$wmi3 = "C07NSU0uUdBScCvKz1UIz8wzNooPLU4tckxOzi/NKwEA" wide
		$wmi4 = "C07NSU0uUdBScCvKz1UIz8wzNor3Sy0pzy/KdkxJLChJLXLOz0vLTC8tSizJzM9TKM9ILUpV8AxwzUtMyklNsS0pKk0FAA=="
		$key1 = "C44MDnH1jXEuLSpKzStxzs8rKcrPCU4tiSlOLSrLTE4tBgA=" wide
		$key2 = "Cy5JLCoBAA==" wide
		$pat1 = "i6420DGtjVWoNqzlAgA=" wide
		$pat2 = "i6420DGtjVWoNtTRNTSrVag2quWsNgYKKVSb1MZUm9ZyAQA=" wide
		$pat3 = "qzaoVag2rFXwCAkJ0K82quUCAA==" wide
		$pat4 = {9D 2A 9A F3 27 D6 F8 EF}

	condition:
		uint16(0)==0x5a4d and $sw and (2 of ($pat*) or 2 of ($priv*) or all of ($disc*) or 2 of ($wmi*) or all of ($key*))
}