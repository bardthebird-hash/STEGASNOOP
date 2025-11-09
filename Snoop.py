# --- 1. ALL IMPORTS GO AT THE TOP ---
from PIL import Image
from rich import print
import argparse
import pyfiglet
import sys
import os # We'll need this for the file-reading
import math
from PIL.ExifTags import TAGS
# --- 2. ALL FUNCTION DEFINITIONS GO NEXT ---
#    (Python must read these *before* they can be called)

def print_banner():
    """
    Prints the cool ASCII art banner for the tool.
    """
    # You can change the font to "slant", "block", "starwars", etc.
    banner = pyfiglet.figlet_format("StegaSnoop", font="speed")
    print(f"[bold green]{banner}[/bold green]")
    print("[bold]A TUI-based Steganography Scanner[/bold]\n")

def check_eof(image_path):
    """
    Detects and decodes data hidden *after* the End-of-File (EOF) marker.
    This is common for simple JPEG steganography.
    """
    print(f"[bold blue]:mag: Starting EOF check on '{image_path}'...[/bold blue]")

    # JPEG End-of-Image marker
    EOF_MARKER = b'\xFF\xD9'

    try:
        # Open the file in 'rb' (read binary) mode
        with open(image_path, 'rb') as f:
            all_bytes = f.read()

        # Find the *last* occurrence of the EOF marker
        marker_position = all_bytes.rfind(EOF_MARKER)

        if marker_position == -1:
            print("[cyan]   - Note: Not a JPEG or no EOF marker found. Skipping EOF check.[/cyan]")
            return

        # Calculate the position *after* the marker
        data_start_position = marker_position + len(EOF_MARKER)
        
        # Check if there is any data after this position
        if data_start_position < len(all_bytes):
            # We found extra data!
            hidden_bytes = all_bytes[data_start_position:]
            print(f"[bold red]:x: EOF Scan: FAIL! Found {len(hidden_bytes)} extra bytes after EOF.[/bold red]")

            # Now, let's try to decode that data as text
            try:
                # Try to decode it as a standard UTF-8 string
                secret_message = hidden_bytes.decode('utf-8')
                print("[bold green]--- DECODED EOF MESSAGE ---[/bold green]")
                print(f"[cyan on black]{secret_message}[/cyan on black]")
            except UnicodeDecodeError:
                # If it fails, it's not text (it's a binary file)
                print("[bold red]--- EOF DATA FOUND ---[/bold red]")
                print("   Found hidden binary data (e.g., a zip file or another image).")

        else:
            # We found the marker, but no data after it
            print("[bold green]:white_check_mark: EOF Scan: PASS. No data found after EOF.[/bold green]")

    except FileNotFoundError:
        print(f"[bold red]Error: File not found at '{image_path}'[/bold red]")
    except Exception as e:
        print(f"[bold red]An error occurred during EOF check: {e}[/bold red]")


def decode_lsb(image_path):
    """
    Detects and decodes a secret message from the LSBs of an image.
    This is the "extractor" part of the tool.
    """
    # This is a good place to add a new line for spacing
    print(f"\n[bold blue]:mag: Starting LSB decode scan on '{image_path}'...[/bold blue]")

    try:
        img = Image.open(image_path)
        
        # --- Handle different image modes (e.g., 'RGB', 'RGBA', 'P' (palette)) ---
        if img.mode != 'RGB':
            try:
                img = img.convert('RGB')
                print("[cyan]   - Note: Image converted to RGB for analysis.[/cyan]")
            except Exception as e:
                print(f"[bold red]Error: Failed to convert image to RGB. {e}[/bold red]")
                return

        pixel_data = img.load()
        width, height = img.size

        bit_buffer = []
        secret_message_bytes = []
        message_found = False

        # Loop over every pixel, row by row
        for y in range(height):
            if message_found:
                break 
            
            for x in range(width):
                r, g, b = pixel_data[x, y]

                # 1. Extract the LSB from each channel
                bit_r = r & 1
                bit_g = g & 1
                bit_b = b & 1

                # 2. Add bits to our buffer, in order (R, G, B)
                bit_buffer.append(bit_r)
                bit_buffer.append(bit_g)
                bit_buffer.append(bit_b)

                # 3. Check if we have a full byte (8 bits)
                while len(bit_buffer) >= 8:
                    byte_bits = bit_buffer[:8]
                    bit_buffer = bit_buffer[8:] 
                    
                    bit_string = "".join(map(str, byte_bits))
                    new_byte_value = int(bit_string, 2)

                    # 5. Check for the "stop" signal (null byte)
                    if new_byte_value == 0:
                        message_found = True
                        break 
                    
                    secret_message_bytes.append(new_byte_value)
                
                if message_found:
                    break 

        # --- After the loops are done, try to decode the message ---
        
        if not secret_message_bytes:
            print("[bold green]:white_check_mark: LSB Scan: No hidden message found.[/bold green]")
            return

        else: print("[bold yellow]:key: LSB Scan: Found unverified data[/bold yellow]")
        
        try:
            secret_bytes = bytes(secret_message_bytes)
            secret_message = secret_bytes.decode('utf-8')
            
            print("[bold green]--- DECODED LSB MESSAGE ---[/bold green]")
            print(f"[cyan on black]{secret_message}[/cyan on black]")

        except UnicodeDecodeError:
            print("[bold red]--- LSB DATA FOUND ---[/bold red]")
            print(f"   Found [cyan]{len(secret_message_bytes)}[/cyan] bytes of non-text binary data.")

    except FileNotFoundError:
        # This check is technically redundant, but good to have
        print(f"[bold red]Error: File not found at '{image_path}'[/bold red]")
    except Exception as e:
        print(f"[bold red]An error occurred during LSB decoding: {e}[/bold red]")
        print("   This could be a corrupted file or an unsupported format.")

def calculate_entropy(file_path):
    """
    Calculates the Shannon entropy of a file.
    High entropy (e.g., > 7.5) suggests encryption or compression.
    """
    print(f"\n[bold blue]:dna: Starting Entropy Analysis on '{file_path}'...[/bold blue]")
    
    try:
        with open(file_path, 'rb') as f:
            all_bytes = f.read()

        if not all_bytes:
            print("[cyan]   - Note: File is empty. Entropy is 0.[/cyan]")
            return 0

        # 1. Count the frequency of each byte (0-255)
        byte_counts = [0] * 256
        for byte in all_bytes:
            byte_counts[byte] += 1
        
        # 2. Calculate the probability of each byte
        file_size = len(all_bytes)
        probabilities = [count / file_size for count in byte_counts if count > 0]
        
        # 3. Calculate the Shannon entropy
        # H = -SUM(p(i) * log2(p(i)))
        entropy = -sum(p * math.log2(p) for p in probabilities)
        
        # 4. Report the result
        print(f"   - Shannon Entropy: [bold]{entropy:.4f}[/bold] (out of 8.0)")

        if entropy > 7.5:
            print(f"[bold red]:x: Entropy Scan: HIGH! (Score: {entropy:.4f})[/bold red]")
            print("   This file is highly random, suggesting it is")
            print("   [bold]encrypted[/bold] or [bold]compressed[/bold] (e.g., a .zip, .rar, or .jpg).")
        elif entropy > 6.0:
            print(f"[bold yellow]:key: Entropy Scan: MEDIUM (Score: {entropy:.4f})[/bold yellow]")
            print("   This file has mixed data, possibly a document or executable.")
        else:
            print(f"[bold green]:white_check_mark: Entropy Scan: LOW (Score: {entropy:.4f})[/bold green]")
            print("   This file is likely uncompressed text or simple data.")
            
        return entropy

    except FileNotFoundError:
        print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
    except Exception as e:
        print(f"[bold red]An error occurred during entropy analysis: {e}[/bold red]")

import math
import os
from rich import print

def calculate_entropy(file_path):
    """
    Calculates the Shannon entropy of a file.
    High entropy (e.g., > 7.5) suggests encryption or compression.
    """
    print(f"\n[bold blue]:dna: Starting Entropy Analysis on '{file_path}'...[/bold blue]")
    
    try:
        with open(file_path, 'rb') as f:
            all_bytes = f.read()

        if not all_bytes:
            print("[cyan]   - Note: File is empty. Entropy is 0.[/cyan]")
            return 0

        # 1. Count the frequency of each byte (0-255)
        byte_counts = [0] * 256
        for byte in all_bytes:
            byte_counts[byte] += 1
        
        # 2. Calculate the probability of each byte
        file_size = len(all_bytes)
        probabilities = [count / file_size for count in byte_counts if count > 0]
        
        # 3. Calculate the Shannon entropy
        # H = -SUM(p(i) * log2(p(i)))
        entropy = -sum(p * math.log2(p) for p in probabilities)
        
        # 4. Report the result
        print(f"   - Shannon Entropy: [bold]{entropy:.4f}[/bold] (out of 8.0)")

        if entropy > 7.5:
            print(f"[bold red]:x: Entropy Scan: HIGH! (Score: {entropy:.4f})[/bold red]")
            print("   This file is highly random, suggesting it is")
            print("   [bold]encrypted[/bold] or [bold]compressed[/bold] (e.g., a .zip, .rar, or .jpg).")
        elif entropy > 6.0:
            print(f"[bold yellow]:key: Entropy Scan: MEDIUM (Score: {entropy:.4f})[/bold yellow]")
            print("   This file has mixed data, possibly a document or executable.")
        else:
            print(f"[bold green]:white_check_mark: Entropy Scan: LOW (Score: {entropy:.4f})[/bold green]")
            print("   This file is likely uncompressed text or simple data.")
            
        return entropy

    except FileNotFoundError:
        print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
    except Exception as e:
        print(f"[bold red]An error occurred during entropy analysis: {e}[/bold red]")




import math
import os
from rich import print

def calculate_entropy(file_path):
    """
    Calculates the Shannon entropy of a file.
    High entropy (e.g., > 7.5) suggests encryption or compression.
    """
    print(f"\n[bold blue]:dna: Starting Entropy Analysis on '{file_path}'...[/bold blue]")
    
    try:
        with open(file_path, 'rb') as f:
            all_bytes = f.read()

        if not all_bytes:
            print("[cyan]   - Note: File is empty. Entropy is 0.[/cyan]")
            return 0

        # 1. Count the frequency of each byte (0-255)
        byte_counts = [0] * 256
        for byte in all_bytes:
            byte_counts[byte] += 1
        
        # 2. Calculate the probability of each byte
        file_size = len(all_bytes)
        probabilities = [count / file_size for count in byte_counts if count > 0]
        
        # 3. Calculate the Shannon entropy
        # H = -SUM(p(i) * log2(p(i)))
        entropy = -sum(p * math.log2(p) for p in probabilities)
        
        # 4. Report the result
        print(f"   - Shannon Entropy: [bold]{entropy:.4f}[/bold] (out of 8.0)")

        if entropy > 7.5:
            print(f"[bold red]:x: Entropy Scan: HIGH! (Score: {entropy:.4f})[/bold red]")
            print("   This file is highly random, suggesting it is")
            print("   [bold]encrypted[/bold] or [bold]compressed[/bold] (e.g., a .zip, .rar, or .jpg).")
        elif entropy > 6.0:
            print(f"[bold yellow]:key: Entropy Scan: MEDIUM (Score: {entropy:.4f})[/bold yellow]")
            print("   This file has mixed data, possibly a document or executable.")
        else:
            print(f"[bold green]:white_check_mark: Entropy Scan: LOW (Score: {entropy:.4f})[/bold green]")
            print("   This file is likely uncompressed text or simple data.")
            
        return entropy

    except FileNotFoundError:
        print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
    except Exception as e:
        print(f"[bold red]An error occurred during entropy analysis: {e}[/bold red]")


# --- Add this to your IMPORTS at the top ---
from PIL.ExifTags import TAGS

# --- This is the UPGRADED function ---
def check_metadata(image_path):
    """
    Scans the image's EXIF metadata for *all* text fields,
    and highlights suspicious ones.
    """
    print(f"\n[bold blue]:scroll: Starting EXIF Metadata scan...[/bold blue]")
    
    try:
        img = Image.open(image_path)
        exif_data = img.getexif()

        if not exif_data:
            print("[bold green]:white_check_mark: EXIF Scan: PASS. No EXIF data found.[/bold green]")
            return

        found_suspicious = False
        found_any_text = False
        
        # These are the tags we'll highlight
        SUSPICIOUS_TAGS = ["UserComment", "ImageDescription", "Artist", "Copyright"]
        
        for (tag_id, value) in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            
            # We only care about text-based tags
            if isinstance(value, str) or isinstance(value, bytes):
                found_any_text = True
                value_str = ""
                
                # On Windows, 'value' might be bytes, so let's decode it safely
                try:
                    if isinstance(value, bytes):
                        # Try to decode, ignoring errors from weird characters
                        value_str = value.decode('utf-8', errors='ignore').strip()
                    else:
                        value_str = str(value).strip()
                except:
                    continue # Skip if it's junk data we can't decode

                # Skip empty tags
                if not value_str:
                    continue
                
                # --- This is the new "talkative" logic ---
                if tag_name in SUSPICIOUS_TAGS:
                    print(f"[bold yellow]:key: Suspicious tag '{tag_name}':[/bold yellow] [cyan on black]{value_str}[/cyan on black]")
                    found_suspicious = True
                else:
                    # It's not suspicious, but we'll "tell you what it is"
                    # We'll truncate it ([:70]) so it doesn't flood your screen
                    print(f"   - Found text in '{tag_name}': [cyan]{value_str[:70]}...[/cyan]")

        
        if not found_any_text:
            print("[bold green]:white_check_mark: EXIF Scan: PASS. No text-based metadata found.[/bold green]")
        elif not found_suspicious:
            print("[bold green]:white_check_mark: EXIF Scan: PASS. No suspicious data found (but other text was present).[/bold green]")

    except Exception as e:
        print(f"[cyan]   - Note: Could not read EXIF data. (File may be corrupt or unsupported).[/cyan]")



# This dictionary holds the "Magic Numbers" (file signatures) we know.
# We can easily add more to this list!
# (File extension, Magic Bytes)
MAGIC_NUMBERS = {
    # Images
    "jpg": b'\xFF\xD8\xFF',   # JPEGs
    "jpeg": b'\xFF\xD8\xFF',  # JPEGs
    "png": b'\x89\x50\x4E\x47', # (PNG)
    "gif": b'\x47\x49\x46\x38', # (GIF)
    "webp": b'\x52\x49\x46\x46', # (RIFF) ... followed by WEBP
    
    # Archives / Executables (Suspicious!)
    "zip": b'\x50\x4B\x03\x04', # (PK.. - a ZIP file)
    "exe": b'\x4D\x5A',         # (MZ - a Windows .exe)
    "rar": b'\x52\x61\x72\x21', # (Rar!)
}

def check_magic_numbers(file_path):
    """
    Checks the file's "magic numbers" (first few bytes) to see
    if its contents match its file extension. Detects file deception.
    """
    print(f"\n[bold blue]:dna: Starting File Deception (Magic Number) scan...[/bold blue]")
    
    try:
        # Get the file's extension (e.g., ".jpg")
        # os.path.splitext gives ('file_name', '.jpg')
        file_name, file_ext_with_dot = os.path.splitext(file_path)
        
        # Clean it up: ".jpg" -> "jpg"
        file_ext = file_ext_with_dot[1:].lower() 

        if file_ext not in MAGIC_NUMBERS:
            print(f"[cyan]   - Note: File type '{file_ext}' is not in our magic number database. Skipping.[/cyan]")
            return

        # Get the "expected" magic bytes from our database
        expected_bytes = MAGIC_NUMBERS[file_ext]
        
        # Read the *actual* first few bytes from the file
        with open(file_path, 'rb') as f:
            # Read just enough bytes to match our check
            actual_bytes = f.read(len(expected_bytes)) 
        
        # Now, compare them!
        if actual_bytes == expected_bytes:
            print(f"[bold green]:white_check_mark: File Type Scan: PASS. File is a real '{file_ext}'.[/bold green]")
        else:
            print(f"[bold red]:x: File Type Scan: FAIL! This file is a '{file_ext}' by name,[/bold red]")
            
            # Bonus check: Let's see if we know what it *really* is
            found_match = False
            for (real_type, magic_bytes) in MAGIC_NUMBERS.items():
                if actual_bytes.startswith(magic_bytes):
                    print(f"   but its contents look like a [bold]{real_type}[/bold] file! This is a RED FLAG.")
                    found_match = True
                    break
            
            if not found_match:
                 print("   and its contents [bold]DO NOT[/bold] match its extension!")

    except FileNotFoundError:
        print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
    except Exception as e:
        print(f"[bold red]An error occurred during Magic Number check: {e}[/bold red]")
# --- 3. THE "MAIN" FUNCTION GOES HERE ---
#    (This function *calls* all the functions defined above)

def main():
    """
    This is the main "controller" for our program.
    """
    
    # 1. Set up the command-line argument parser
    parser = argparse.ArgumentParser(
        description="StegaSnoop-TUI: A TUI-based Steganography Scanner",
        epilog="Example: python stegasnoop_tui.py -i my_image.png"
    )
    # We make the image argument *required*
    parser.add_argument(
        "-i", "--image", 
        help="Path to the image file to scan", 
        required=True,
    nargs='+'
    )
    
    # 2. Get the arguments from the user
    args = parser.parse_args()
    # 3. Run our functions in order!
    
    # Print the cool banner first
    print_banner()
    image_paths_list = args.image
    for image_path_string in image_paths_list:
        print(f"\n[bold purple]=== Scanning File: {image_path_string} ===[/bold purple]")
        if not os.path.exists(image_path_string):
            print(f"[bold red]Error: File not found at '{image_path_string}'. Skipping.[/bold red]")
            continue
    # Get the path from the args
        image_path = args.image
    
    # Check if the file exists before we do anything
        if not os.path.exists(image_path_string):
            print(f"[bold red]Error: File not found at '{image_path}'[/bold red]")
            sys.exit(1) # Exit the script with an error

    # Run the EOF check
        check_magic_numbers(image_path_string)
        check_eof(image_path_string)
    
    # Run the LSB check
        decode_lsb(image_path_string)
    


        calculate_entropy(image_path_string)
        check_metadata(image_path_string)
    print("\n[bold]Scan complete.[/bold]")


# --- 4. THE "KEY" TO START THE PROGRAM ---
#    (This must be at the *very bottom* of the file)
#
# This tells Python: "When you run this file directly,
# find the function named 'main()' and run it."
    print("\n[bold]=== All scans complete. ===[/bold]")
if __name__ == "__main__":
    main()

