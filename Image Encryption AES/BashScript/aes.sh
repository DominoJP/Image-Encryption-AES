#!/bin/bash


# Directory where input images are stored
input_dir="InputImages"

#conversion from bytes to kilobytes
to_KB=1000

# Check if AES_Encryption.exe exists in the current directory
if [[ ! -f AES_Encryption ]]; then
    echo "Error: AES_Encryption not found in the current directory."
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
        echo ""
        continue #skip this iteration if this file is already encrypted
    fi
    image_info=$(file "$image_file")
    image_size=$(stat -c%s "$image_file")
    image_size=$(expr "$image_size" / $to_KB)
    
    # Generate a random key with length between 16 and 32 characters
    key_128=IQzHDIf5TYdnWw3G
    key_192=dVbX6u6N3ufPqkF00DPZnjc6
    key_256=aXWmcGmZ%SxHKUPCfuqC53JF05s3C3KW
    
    randomIndex=$((RANDOM % 3))

    #select the key based on the random number
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



    echo -e "---------- "File $index: $image_file done " ----------" >> "$output_file"

    echo -e "Key: $key" >> "$output_file"

    echo "----------Encrypting file $index----------"
    echo "$image_info"
    echo "size: $image_size KB"
    echo "Key: $key (Length: $key_length) (AES-$aes_type)"
    
    # Run AES_Encryption.exe for parallel run and sequential run
    ./AES_Encryption "$image_file" "$key" >> "$output_file"
    echo -e "" >> "$output_file"
    
    echo -e "" >> "$output_file"
    wait  # Ensure each file runs both modes sequentially but each file is processed in parallel
    
    echo ""
    ((index++))
done

echo "Encryption completed for all files in $input_dir."
