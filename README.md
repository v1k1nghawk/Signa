# Signa

* _NAME:_ Signa - File fingerprinting</ins>

* _SYNOPSIS:_ **Signa** -i <ins>INPUTFILE</ins> -o <ins>OUTPUTFILE</ins> [-bs <ins>BS</ins>] [--verbose <ins>FLAG</ins>]</ins>

* _DESCRIPTION:_ Creates a MD5-based file's fingerprint. For each <ins>BS</ins>Mb block of the <ins>INPUTFILE</ins> the program calculates the MD5 hash value and stores it in the <ins>OUTPUTFILE</ins>. Last <ins>INPUTFILE</ins>'s data block padded with zeroes to the block size if needed before hashing. So the <ins>OUTPUTFILE</ins> contains <ins>BS</ins> MD5 hash values, one for each <ins>OUTPUTFILE</ins>'s data block.</ins>


**-i**, **--input** <ins>INPUTFILE</ins></ins>
	path to the input file</ins>


**-o**, **--output** <ins>OUTPUTFILE</ins></ins>
	path to the output file</ins>


**-bs**, **--block_size** <ins>BS</ins></ins>
	size of the input file's hashing unit (Mb, a natural number less than or equal to 1 Gb), default: 1 Mb</ins>


**-v**, **--verbose** <ins>FLAG</ins></ins>
	print detailed information during computing, default: false</ins>


