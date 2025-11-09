StegaSnoop-TUI A Multi-Layer Image Forensics scanner

StegaSnoop-TUI is a command-line forensic tool built in Python

It is designed to be a fast, simple, and powerful "first-look" tool for digital forensics. It scans any file (with a focus on images) using a 5-layer scanning process to detect hidden data, steganography, and file-based deception.

This tool is designed to run in a TUI (Terminal User Interface) using the 'rich' library for clean, color-coded, and easy-to-read reports.

FEATURES

StegaSnoop-TUI combines 5 powerful forensic scanners into one tool:

File Deception (Magic Number) Check:
Detects if a file is lying about its type. It checks the file's "magic numbers" (first few bytes) against its file extension (e.g., warns if a .jpg file is actually a hidden .zip or .exe).

End-of-File (EOF) Scan:
Detects if a hacker has appended extra data to the end of a file. It locates the proper EOF marker (e.g., FF D9 for JPEG) and reports any data hidden after it.

LSB (Least Significant Bit) Decoder:
The classic steganography check. It scans the LSBs of every pixel's color channels (RGB) to find and extract hidden text messages.

Entropy Analysis:
Scans the file's "randomness" (Shannon entropy). A very high entropy score (e.g., > 7.5) is a massive red flag for hidden encrypted data or a compressed archive.

EXIF Metadata Scanner:
Dumps all text-based metadata stored inside an image (e.g., camera info, timestamps). It specifically highlights suspicious, user-editable tags like "UserComment" or "Artist" where messages are often hidden.

Other Features:

Batch Processing: Scan multiple files at once.

Cross-Platform: Runs on any system with Python 3 (built and tested on Kali Linux).

REQUIREMENTS

Python 3.x

Python packages: rich, pillow, pyfiglet

INSTALLATION & SETUP (for Kali Linux)

Clone the repository:
git clone [YOUR GITHUB REPO URL HERE]
cd StegaSnoop-TUI

(Recommended) Create a Python virtual environment:
python3 -m venv venv
source venv/bin/activate

Install the required Python packages:
pip install rich pillow pyfiglet

(CRITICAL FOR EXIF SCANNER) Install JPEG/ZLIB support libraries:
On Debian/Kali, Pillow needs system-level libraries to read EXIF data from JPEGs.

sudo apt-get update
sudo apt-get install libjpeg-dev zlib1g-dev

Re-install Pillow to build with the new libraries:
pip uninstall pillow
pip install pillow

Run the tool!
python snoop.py --help

USAGE

The tool is run from the command line using the -i (or --image) flag.

Scan a single file:
python snoop.py -i /path/to/my_image.jpg

Scan multiple files at once (batch scan):
python snoop.py -i image1.png image2.jpg /home/kali/Desktop/suspicious_file.gif

AUTHORS

Kris Rucker

Jack Dumbeck
