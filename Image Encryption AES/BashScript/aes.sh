#!/bin/bash

# Default directory where input images are stored
input_dir="InputImages"
# Conversion from bytes to kilobytes
to_KB=1000

# Default executable path
exec_path="./AES_Encryption"

# Variables for the run mode
run_mode="both"

# Parse command-line arguments
while getopts "d:e:sph" opt; do
    case $opt in
        d) input_dir="$OPTARG" ;;
        e) exec_path="$OPTARG" ;;
        s) run_mode="sequential" ;;
        p) run_mode="parallel" ;;
        h) echo "Usage: $0 [-d input_directory] [-e executable_path] [-s (sequential)] [-p (parallel)]" ; exit 0 ;;
        *) echo "Usage: $0 [-d input_directory] [-e executable_path] [-s (sequential)] [-p (parallel)]" ; exit 1 ;;
    esac
done

# Check if the executable exists in the specified path
if [[ ! -f "$exec_path" ]]; then
    echo "Error: AES_Encryption not found at $exec_path."
    exit 1
fi

program_name="AES_Encryption"
output_file="${program_name}_output.txt"

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

    # Generate a random key with length between 16 and 32 characters
    key_128=IQzHDIf5TYdnWw3G
    key_192=dVbX6u6N3ufPqkF00DPZnjc6
    key_256=aXWmcGmZ%SxHKUPCfuqC53JF05s3C3KW

    randomIndex=$((RANDOM % 3))

    # Select the key based on the random number
    case $randomIndex in
        0)  
            key="$key_128"
            key_length=16
            aes_type=128 ;;
        1)  
            key="$key_192" 
            key_length=24
            aes_type=192 ;;
        2)  
            key="$key_256" 
            key_length=32
            aes_type=256 ;;
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
            "$exec_path" -s "$image_file" "$key" >> "$output_file" ;;
        "parallel")
            "$exec_path" -p "$image_file" "$key" >> "$output_file" & ;;
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
