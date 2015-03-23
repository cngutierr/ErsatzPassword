# ErsatzPassword

ErsatzPassword is a PAM_UNIX module that utlizes the Yubikey HSM to generate cryptographic password hashes in a cleaver way. If an attacker steals the hashed password file (e.g., etc/shadow, /etc/master.passwd) and attempts to crack the password via a dictionary bruteforce attack, the ersatz “fake” passwords are revieled rather than the true password. 
The detailed design of this tool can be found in [here](https://www.cerias.purdue.edu/assets/pdf/bibtex_archive/2015-2.pdf).
