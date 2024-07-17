rule TELEKOM_SECURITY_Crylock_Hta : FILE
{
	meta:
		description = "Detects CryLock ransomware how_to_decrypt.hta ransom note"
		author = "Thomas Barabosch, Telekom Security"
		id = "cf6ba6d2-beca-5da0-bb2d-0b8b52418a5e"
		date = "2021-06-28"
		modified = "2021-07-08"
		reference = "TBA"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/crylock/crylock_20210706.yar#L29-L53"
		license_url = "N/A"
		logic_hash = "3b603a395f872d74d54b98a8ac6e6eb71c3bd0f076b4c834fcb4922e2aaa58b9"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$s1 = "var main_contact =" ascii
		$s2 = "var max_discount =" ascii
		$s3 = "<title>CryLock</title>" ascii
		$s4 = "var discount_date = new Date(" ascii
		$s5 = "var main_contact =" ascii
		$s6 = "var hid = " ascii
		$s7 = "var second_contact = " ascii
		$s8 = "document.getElementById('main_contact').innerHTML = main_contact;" ascii
		$s9 = "document.getElementById('second_contact').innerHTML = second_contact;" ascii
		$s10 = "document.getElementById('hid').innerHTML = hid;" ascii
		$s11 = "be able to decrypt your files. Contact us" ascii
		$s12 = "Attention! This important information for you" ascii
		$s13 = "higher will become the decryption key price" ascii
		$s14 = "Before payment, we can decrypt three files for free." ascii

	condition:
		filesize <100KB and 8 of ($s*)
}