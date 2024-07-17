rule RUSSIANPANDA_Golang_Base64_Enc : FILE
{
	meta:
		description = "Detects Base64 Encoding and Decoding patterns in Golang binaries"
		author = "RussianPanda"
		id = "6330e005-9c67-5acd-9063-aa7e30e92f5f"
		date = "2024-01-10"
		modified = "2024-01-14"
		reference = "https://unprotect.it/technique/base64/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Techniques/golang_base64_enc.yar#L1-L18"
		license_url = "N/A"
		hash = "509a359b4d0cd993497671b91255c3775628b078cde31a32158c1bc3b2ce461c"
		logic_hash = "72cf3ee948df9c4ce593f16a49397e79fdc5ecc3264b3685bbc54f60ed1278bd"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {62 61 73 65 36 34 2e 53 74 64 45 6e 63 6f 64 69 6e 67 2e 45 6e 63 6f 64 65 54 6f 53 74 72 69 6e 67 28 [0-15] 29}
		$s2 = {62 61 73 65 36 34 2e 53 74 64 45 6e 63 6f 64 69 6e 67 2e 44 65 63 6f 64 65 53 74 72 69 6e 67 28 [0-15] 29}
		$s3 = {69 66 20 65 72 72 20 21 3D 20 6E 69 6C 20 7B}
		$s4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	condition:
		all of ($s*) and uint16(0)==0x5A4D
}