#!/usr/bin/env bash
#===============================================================================
# Script Name   : extract-ctf-flag.sh
#
# Purpose       : Extracts CTF flags hidden in ASCII-art "bubbles" of the form
#                 ( x ) or (x) either:
#                   1) Directly from a file inside a disk image (via Sleuth Kit's icat), or
#                   2) From a plain text file that already contains the ASCII-art.
#
#                 Typical ASCII-art pattern this script is meant for:
#                   ( p ) ( i ) ( c ) ( o ) ( C ) ( T ) ( F ) ( { ) ...
#
# Author        : Danny Cologero
# Date Created  : 10-15-2025
# Last Modified : 10-15-2025
# Version       : 1.2
#
# ==============================================================================
# VERY DETAILED USAGE INSTRUCTIONS
# ==============================================================================
#
# 0. PREREQUISITES
#    ---------------------------------
#    You need the following tools installed and available in your PATH:
#
#    - bash   : Default on most Linux systems.
#    - grep   : For pattern matching.
#    - tr     : For stripping characters/newlines.
#    - icat   : From "The Sleuth Kit" (ONLY required in disk image mode).
#
#    To install The Sleuth Kit on Debian/Ubuntu-based systems:
#      sudo apt-get update
#      sudo apt-get install sleuthkit
#
#    To confirm commands exist, you can run:
#      which bash grep tr icat
#
# ------------------------------------------------------------------------------
# 1. SAVE THIS SCRIPT
#    ---------------------------------
#    1. Open a terminal.
#    2. Navigate to the directory where you want to store the script, for example:
#         cd ~/scripts
#    3. Create the script file:
#         nano extract-flag.sh
#    4. Paste the ENTIRE contents of this script into the editor.
#    5. Save and exit:
#         - In nano: Press Ctrl+O, Enter, then Ctrl+X.
#
# ------------------------------------------------------------------------------
# 2. MAKE THE SCRIPT EXECUTABLE
#    ---------------------------------
#    Run:
#      chmod +x extract-flag.sh
#
#    This allows you to execute it as:
#      ./extract-flag.sh
#
# ------------------------------------------------------------------------------
# 3. UNDERSTAND THE TWO MODES OF OPERATION
#    ---------------------------------
#    This script has TWO distinct modes:
#
#    (A) DISK IMAGE MODE (using icat)
#        - Use this when the ASCII-art flag is stored inside a file that lives
#          within a disk image (e.g., .img, .dd) and you know:
#             * The image file name
#             * The inode number of the file within the image
#             * The filesystem offset (in bytes) inside the image
#
#        Syntax:
#          ./extract-flag.sh <image_file> <inode_number> <offset>
#
#        Example:
#          ./extract-flag.sh dds2-alpine.flag.img 18291 2048
#
#        Explanation of arguments:
#          - <image_file>   : Path to the disk image (e.g., dds2-alpine.flag.img)
#          - <inode_number> : Inode number of the target file (e.g., 18291)
#          - <offset>       : Byte offset where the filesystem starts (e.g., 2048)
#
#        Where do you get inode and offset from?
#          - offset: Often provided by challenge docs or found using mmls.
#          - inode:  Found via tools like fls or ils from Sleuth Kit.
#
#        What the script does in this mode:
#          1. Uses: icat -o <offset> <image_file> <inode_number>
#             to extract the raw content of the file from the disk image.
#          2. Pipes that output to a pattern extractor that:
#               - Finds all occurrences of "( x )" or "(x)" style groups.
#               - Removes parentheses, spaces, and newlines.
#               - Reconstructs the flag as a single continuous string.
#
#    (B) TEXT FILE MODE (already-extracted ASCII-art file)
#        - Use this when you already have the ASCII-art in a plain text file
#          (for example, copied out of a tool or provided in a file).
#
#        Syntax:
#          ./extract-flag.sh -f <ascii_art_file>
#
#        Example:
#          ./extract-flag.sh -f flag.txt
#
#        Where:
#          - <ascii_art_file> is a text file containing lines like:
#              ( p ) ( i ) ( c ) ( o ) ( C ) ( T ) ( F ) ( { ) ...
#
#        What the script does in this mode:
#          1. Reads the contents of <ascii_art_file>.
#          2. Extracts the character inside each "( ... )" group.
#          3. Strips parentheses, spaces, and newlines.
#          4. Prints the reconstructed flag.
#
# ------------------------------------------------------------------------------
# 4. CONCRETE EXAMPLES
#    ---------------------------------
#
#    Example 1: Using disk image mode (your original workflow)
#
#      ./extract-flag.sh dds2-alpine.flag.img 18291 2048
#
#      This will:
#        - Run: icat -o 2048 dds2-alpine.flag.img 18291
#        - Pipe the output through the pattern extractor.
#        - Print something like:
#            picoCTF{f0r3n_s1c4t0r_n0v1c3_db59daa5}
#        - Then print:
#            [PASS] Non-empty flag extracted successfully.
#
#    Example 2: Using text file mode
#
#      Suppose you saved the ASCII-art into a file:
#        flag.txt
#
#      Then run:
#        ./extract-flag.sh -f flag.txt
#
#      You will see:
#        picoCTF{f0r3n_s1c4t0r_n0v1c3_db59daa5}
#        [PASS] Non-empty flag extracted successfully.
#
# ------------------------------------------------------------------------------
# 5. PASS / FAIL LOGIC
#    ---------------------------------
#    After extraction, the script:
#      - Captures the reconstructed string in a variable called FLAG.
#      - If FLAG is non-empty:
#           - Prints the flag.
#           - Prints:
#               [PASS] Non-empty flag extracted successfully.
#           - Exits with status code 0.
#      - If FLAG is empty:
#           - Prints:
#               [FAIL] No flag-like patterns were extracted. Check input and parameters.
#           - Exits with status code 1.
#
#    This helps you quickly see if the extraction worked or if you need to
#    revisit the image, inode, offset, or text file input.
#
# ------------------------------------------------------------------------------
# 6. COMMON ERRORS AND HOW TO FIX THEM
#    ---------------------------------
#
#    a) "Permission denied"
#       - You likely forgot to make the script executable.
#       - Fix with:
#           chmod +x extract-flag.sh
#
#    b) "[ERROR] Required command 'icat' not found"
#       - You are using image mode but Sleuth Kit is not installed.
#       - Install it (Debian/Ubuntu):
#           sudo apt-get update
#           sudo apt-get install sleuthkit
#
#    c) "[ERROR] File not found: <something>"
#       - The specified image file or text file does not exist at the path given.
#       - Check the file path with:
#           ls -l <that_path>
#
# ------------------------------------------------------------------------------
# 7. OUTPUT
#    ---------------------------------
#    - On success:
#          <flag string>
#          [PASS] Non-empty flag extracted successfully.
#
#    - On failure (no patterns found):
#          [FAIL] No flag-like patterns were extracted. Check input and parameters.
#
#===============================================================================

set -euo pipefail

#---------------------------
# Usage / help function
#---------------------------
usage() {
  echo "Usage:"
  echo "  Image mode (using icat):"
  echo "    $0 <image_file> <inode_number> <offset>"
  echo
  echo "  Text file mode (already extracted ASCII art):"
  echo "    $0 -f <ascii_art_file>"
  echo
  echo "Examples:"
  echo "  $0 dds2-alpine.flag.img 18291 2048"
  echo "  $0 -f flag.txt"
  exit 1
}

#---------------------------
# Core extraction function
#---------------------------
extract_from_stream() {
  # Matches patterns like:
  #   ( p )   (p)   (   x   )
  # and extracts only the inner character(s), then joins them.
  # We use '|| true' so that if grep finds no matches (exit 1),
  # the function still returns cleanly and we can handle that as FAIL.
  local extracted
  extracted=$(grep -Eo '\( *. *\)' 2>/dev/null \
    | tr -d '() ' \
    | tr -d '\n' \
    || true)
  printf '%s' "$extracted"
}

MODE="image"
TEXTFILE=""
IMAGE=""
INODE=""
OFFSET=""
FLAG=""

#---------------------------
# Argument parsing
#---------------------------
if [ "$#" -eq 0 ]; then
  usage
fi

if [ "$1" = "-f" ] || [ "$1" = "--file" ]; then
  # Text file mode
  if [ "$#" -ne 2 ]; then
    usage
  fi
  MODE="file"
  TEXTFILE=$2
else
  # Image mode
  if [ "$#" -ne 3 ]; then
    usage
  fi
  MODE="image"
  IMAGE=$1
  INODE=$2
  OFFSET=$3
fi

#---------------------------
# Basic dependency checks
#---------------------------
need_cmds=(grep tr)

if [ "$MODE" = "image" ]; then
  need_cmds+=(icat)
fi

for cmd in "${need_cmds[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[ERROR] Required command '$cmd' not found in PATH." >&2
    exit 1
  fi
done

#---------------------------
# Run in the selected mode
#---------------------------
if [ "$MODE" = "image" ]; then
  # Image mode: use icat to pull file contents from the disk image
  FLAG=$(icat -o "$OFFSET" "$IMAGE" "$INODE" | extract_from_stream)
else
  # File mode: read from plain text file
  if [ ! -f "$TEXTFILE" ]; then
    echo "[ERROR] File not found: $TEXTFILE" >&2
    exit 1
  fi

  FLAG=$(cat "$TEXTFILE" | extract_from_stream)
fi

#---------------------------
# PASS / FAIL handling
#---------------------------
if [ -n "$FLAG" ]; then
  echo "$FLAG"
  echo "[PASS] Non-empty flag extracted successfully."
  exit 0
else
  echo "[FAIL] No flag-like patterns were extracted. Check input and parameters." >&2
  exit 1
fi
