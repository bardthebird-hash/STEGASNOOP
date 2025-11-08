# --- 1. ALL IMPORTS GO AT THE TOP ---
from PIL import Image
from rich import print
import argparse
import pyfiglet
import sys
import os # We'll need this for the file-reading

# --- 2. ALL FUNCTION DEFINITIONS GO NEXT ---
#    (Python must read these *before* they can be called)

def print_banner():
    """
    Prints the cool ASCII art banner for the tool.
    """
    # You can change the font to "slant", "block", "starwars", etc.
    banner = pyfiglet.figlet_format("StegaSnoop", font="doom")
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

        print("[bold yellow]:key: LSB Scan: Found a hidden message![/bold yellow]")
        
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
        required=True
    )
    
    # 2. Get the arguments from the user
    args = parser.parse_args()

    # 3. Run our functions in order!
    
    # Print the cool banner first
    print_banner()

    # Get the path from the args
    image_path = args.image
    
    # Check if the file exists before we do anything
    if not os.path.exists(image_path):
        print(f"[bold red]Error: File not found at '{image_path}'[/bold red]")
        sys.exit(1) # Exit the script with an error

    # Run the EOF check
    check_eof(image_path)
    
    # Run the LSB check
    decode_lsb(image_path)
    
    print("\n[bold]Scan complete.[/bold]")


# --- 4. THE "KEY" TO START THE PROGRAM ---
#    (This must be at the *very bottom* of the file)
#
# This tells Python: "When you run this file directly,
# find the function named 'main()' and run it."

if __name__ == "__main__":
    main()
