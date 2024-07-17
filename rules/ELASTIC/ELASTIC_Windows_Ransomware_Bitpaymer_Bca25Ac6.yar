rule ELASTIC_Windows_Ransomware_Bitpaymer_Bca25Ac6 : BETA FILE MEMORY
{
	meta:
		description = "Identifies BITPAYMER ransomware"
		author = "Elastic Security"
		id = "bca25ac6-e351-4823-be75-b0661c89588a"
		date = "2020-06-25"
		modified = "2021-08-23"
		reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Bitpaymer.yar#L22-L48"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "7670f9dafacc8fc5998c1974af66ede388c0997545da067648fec4fd053f0001"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "2ecc7884d47ca7dbba30ba171b632859914d6152601ea7b463c0f52be79ebb8c"
		threat_name = "Windows.Ransomware.Bitpaymer"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "RWKGGE.PDB" fullword
		$a2 = "*Qf69@+mESRA.RY7*+6XEF#NH.pdb" fullword
		$a3 = "04QuURX.pdb" fullword
		$a4 = "9nuhuNN.PDB" fullword
		$a5 = "mHtXGC.PDB" fullword
		$a6 = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt_new.pdb" fullword
		$a7 = "C:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword
		$a8 = "k:\\softcare\\release\\h2O.pdb" fullword

	condition:
		1 of ($a*)
}