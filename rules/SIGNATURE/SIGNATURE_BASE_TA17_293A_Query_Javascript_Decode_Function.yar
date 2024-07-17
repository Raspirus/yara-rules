rule SIGNATURE_BASE_TA17_293A_Query_Javascript_Decode_Function : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "other (modified by Florian Roth)"
		id = "bc206ab3-a86b-5abe-ae84-15abab838d4e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_293A.yar#L122-L140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8b42c67bdcdbb7c38128d8956904baa524d155b1e6957c5c1b5bc28fd8a57e8a"
		score = 75
		quality = 83
		tags = "FILE"
		name = "Query_Javascript_Decode_Function"

	strings:
		$decode1 = {72 65 70 6C 61 63 65 28 2F 5B 5E 41 2D 5A 61 2D 7A 30 2D 39 5C 2B 5C 2F 5C 3D 5D 2F 67 2C 22 22 29 3B}
		$decode2 = {22 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F 3D 22 2E 69 6E 64 65 78 4F 66 28 ?? 2E 63 68 61 72 41 74 28 ?? 2B 2B 29 29}
		$decode3 = {3D ?? 3C 3C 32 7C ?? 3E 3E 34 2C ?? 3D 28 ?? 26 31 35 29 3C 3C 34 7C ?? 3E 3E 32 2C ?? 3D 28 ?? 26 33 29 3C 3C 36 7C ?? 2C ?? 2B 3D [1-2] 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29 2C 36 34 21 3D ?? 26 26 28 ?? 2B 3D 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29}
		$decode4 = {73 75 62 73 74 72 69 6E 67 28 34 2C ?? 2E 6C 65 6E 67 74 68 29}

	condition:
		filesize <20KB and all of ($decode*)
}