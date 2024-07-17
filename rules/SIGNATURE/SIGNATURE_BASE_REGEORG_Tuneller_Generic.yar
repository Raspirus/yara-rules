rule SIGNATURE_BASE_REGEORG_Tuneller_Generic : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Mandiant"
		id = "a87979b7-2732-5a32-b3f3-a815a58b6589"
		date = "2021-12-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/webshell_regeorg.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "ba22992ce835dadcd06bff4ab7b162f9"
		logic_hash = "1657928875c3cd2d5bf774929b0497d78f0211b321f8a4138cc9b8c80b9f99d6"
		score = 75
		quality = 85
		tags = "FILE"
		date_modified = "2021-12-20"

	strings:
		$s1 = "System.Net.IPEndPoint"
		$s2 = "Response.AddHeader"
		$s3 = "Request.InputStream.Read"
		$s4 = "Request.Headers.Get"
		$s5 = "Response.Write"
		$s6 = "System.Buffer.BlockCopy"
		$s7 = "Response.BinaryWrite"
		$s8 = "SocketException soex"

	condition:
		filesize <1MB and 7 of them
}