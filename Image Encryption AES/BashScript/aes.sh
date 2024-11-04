#!/bin/bash

# This script encrypts image files using AES encryption.
# Configuration:
# - Default input directory: InputImages
# - Default executable path: ./AES_Encryption
# - Default key type: 128-bit AES
# - Run mode: Both parallel and sequential by default


# Default directory where input images are stored
input_dir="InputImages"
# Conversion from bytes to kilobytes
to_KB=1000

# Default executable path
exec_path="./AES_Encryption"

# Variables for the run mode
run_mode="both"
# Default key type
default_key_type=128

# Parse command-line arguments
while getopts "d:e:sphk:" opt; do
    case $opt in
        d) input_dir="$OPTARG" ;;
        e) exec_path="$OPTARG" ;;
        s) run_mode="sequential" ;;
        p) run_mode="parallel" ;;
        k) default_key_type="$OPTARG" ;;
        h) echo "Usage: $0 [-d input_directory] [-e executable_path] [-s (sequential)] [-p (parallel)] [-k key_type (128/192/256)]
    $ & 'Image Encryption AES.exe' <inputFile> <key> [-spde]" ; exit 0 ;;
        *) echo "Usage: $0 [-d input_directory] [-e executable_path] [-s (sequential)] [-p (parallel)] [-k key_type (128/192/256)]
    $ & 'Image Encryption AES.exe' <inputFile> <key> [-spde]" ; exit 1 ;;
    esac
done

# Check if the executable exists in the specified path
if [[ ! -f "$exec_path" ]]; then
    echo "Error: AES_Encryption not found at $exec_path."
    exit 1
fi

program_name="AES_Encryption"
output_file="${program_name}_output.txt"

echo "Starting AES Encryption Script with the following configuration:"
echo "Input directory: $input_dir"
echo "Executable path: $exec_path"
echo "Default key type: AES-$default_key_type"
echo "Run mode: $run_mode"
echo ""

# Overwrite the output file at the start
> "$output_file"

index=1
# Loop through each image file in the input directory
for image_file in "$input_dir"/*; do
    # Check if there are any files in the directory
    if [[ ! -f "$image_file" ]]; then
        echo "No images found in $input_dir."
        exit 1
    fi

    if [[ "$image_file" == *.enc ]]; then
        echo "Skipping this file!"
        echo ""
        continue # Skip this iteration if this file is already encrypted
    fi
    
    image_info=$(file "$image_file")
    image_size=$(stat -c%s "$image_file")
    image_size=$(expr "$image_size" / $to_KB)

    # Keys for different AES types
    key_128=IQzHDIf5TYdnWw3G
    key_192=dVbX6u6N3ufPqkF00DPZnjc6
    key_256=aXWmcGmZ%SxHKUPCfuqC53JF05s3C3KW

    # Select key based on specified key type
    case $default_key_type in
        128)
            key="$key_128"
            key_length=16
            aes_type=128 ;;
        192)
            key="$key_192"
            key_length=24
            aes_type=192 ;;
        256)
            key="$key_256"
            key_length=32
            aes_type=256 ;;
        *)
            echo "Invalid key type specified. Use 128, 192, or 256."
            exit 1 ;;
    esac

    echo -e "---------- File $index: $image_file done ----------" >> "$output_file"
    echo -e "Key: $key" >> "$output_file"

    echo "----------Encrypting file $index----------"
    echo "$image_info"
    echo "Size: $image_size KB"
    echo "Key: $key (Length: $key_length) (AES-$aes_type)"
    
    # Run AES_Encryption with the appropriate mode
    case $run_mode in
        "sequential")
            "$exec_path"  "$image_file" "$key" -s >> "$output_file" ;;
        "parallel")
            "$exec_path"  "$image_file" "$key" -p >> "$output_file" & ;;
        "both")
            "$exec_path" "$image_file" "$key" >> "$output_file" ;;
    esac

    echo -e "" >> "$output_file"
    
    # Ensure each file runs sequentially but each file is processed in parallel
    wait 
    echo ""
    ((index++))
done

echo "Encryption completed for all files in $input_dir."


