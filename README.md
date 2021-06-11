# Signa

_NAME:_ Signa - file fingerprinting


_SYNOPSIS:_ **Signa** -i <ins>INPUTFILE</ins> -o <ins>OUTPUTFILE</ins> [-bs <ins>BS</ins>] [-v <ins>FLAG</ins>]


_DESCRIPTION:_ Checksum calculator, creates a MD5-based file's fingerprint. For each <ins>BS</ins> megabyte block of the <ins>INPUTFILE</ins> the program calculates the MD5 hash value and stores it in the <ins>OUTPUTFILE</ins> (last <ins>INPUTFILE</ins>'s data block padded with zeroes to the block size if needed before hashing). So the <ins>OUTPUTFILE</ins> contains <ins>BS</ins> MD5 hash values, one for each <ins>OUTPUTFILE</ins>'s data block.


**-i**, **--input** <ins>INPUTFILE</ins><br />
	path to the input file


**-o**, **--output** <ins>OUTPUTFILE</ins><br />
	path to the output file


**-bs**, **--block_size** <ins>BS</ins><br />
	size of the input file's hashing unit (Mb, a natural number less than or equal to 1 Gb), default: 1 Mb


**-v**, **--verbose** <ins>FLAG</ins><br />
	print detailed information during computing, default: false


