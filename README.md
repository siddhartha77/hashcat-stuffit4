# hashcat-stuffit4
hashcat kernel for StuffIt4 archives

## Usage

Password is _hashcat_:

hashcat.exe -m 90337 -a 0 d1383d6ddcb2e9af wordlists\weakpass_3w

Get the hash to crack from the MKey resource of the StuffIt archive.

## pass2unstuff.sh

This script will utilize the unstuff CLI from StuffIt Deluxe 15 to try passwords from a list against an archive. Useful for sifting through all the false positives hashcat will generate.
