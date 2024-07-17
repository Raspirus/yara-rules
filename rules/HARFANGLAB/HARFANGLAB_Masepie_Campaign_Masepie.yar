rule HARFANGLAB_Masepie_Campaign_Masepie : FILE
{
	meta:
		description = "Detect MASEPIE from CERT-UA#8399"
		author = "HarfangLab"
		id = "f0a034fa-38d4-5c54-b865-f830f85e245e"
		date = "2024-01-24"
		modified = "2024-01-31"
		reference = "TRR240101;https://cert.gov.ua/article/6276894"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240101/trr240101_yara.yar#L42-L62"
		license_url = "N/A"
		hash = "18f891a3737bb53cd1ab451e2140654a376a43b2d75f6695f3133d47a41952b6"
		logic_hash = "02da8119267978e63e3ee5ecdefb52285718f8875ec64d320f2752460c05588d"
		score = 75
		quality = 78
		tags = "FILE"
		context = "file"

	strings:
		$t1 = "Try it againg" ascii wide fullword
		$t2 = "{user}{SEPARATOR}{k}" ascii wide fullword
		$t3 = "Error transporting file" ascii wide fullword
		$t4 = "check-ok" ascii wide fullword
		$a1 = ".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))" ascii wide fullword
		$a2 = "dec_file_mes(mes, key)" ascii wide fullword
		$a3 = "os.popen('whoami').read()" ascii wide fullword

	condition:
		filesize >2KB and filesize <15MB and (4 of them )
}