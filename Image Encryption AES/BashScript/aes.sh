#!/bin/bash

# Directory where input images are stored
input_dir="InputImages"


# Check if AES_Encryption.exe exists in the current directory
if [[ ! -f AES_Encryption.exe ]]; then
    echo "Error: AES_Encryption.exe not found in the current directory."
    exit 1
fi
program_name="AES_Encryption"
output_file="${program_name}_output.txt"

#overwrite the output file at the start
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
        echo "skipping this file!"
        continue #skip this iteration if this file is already encrypted
    fi

    # TODO: Generate a random key with length between 16 and 32 characters
    key=my_key_length_16
    key_length=16

    # Run the AES encryption executable in parallel and sequential modes
    echo "Encrypting file $index:"
    echo "$image_file with key $key (Length: $key_length)"
    
    # Run AES_Encryption.exe for parallel run and sequential run
    ./AES_Encryption.exe "$image_file" "$key" >> "$output_file"
    wait  # Ensure each file runs both modes sequentially but each file is processed in parallel
    echo "File $index: $image_file done"
    echo ""
    ((index++))
done

echo "Encryption completed for all files in $input_dir."
