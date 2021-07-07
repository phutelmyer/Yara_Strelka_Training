rule intriguing_France_strings {
    meta:
        author = "Derek Thomas & Paul Hutelmyer"
        description = "Matches on suspicious string intriguing_France sample"
        date = "07/15/2021"
        version = "1.0"
        license = "N/A"
        family="N/A"
        sha256_hashes= "N/A"
        weight= 0
        scope ="['testing', 'hunting']"
        intel ="['N/A']"
    strings:
        $string1 = "margaritasexy
	
    condition:
        $string1
}