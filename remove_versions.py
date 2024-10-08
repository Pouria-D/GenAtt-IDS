def remove_versions(input_file, output_file):
    try:
        # Open the input file for reading
        with open(input_file, 'r') as infile:
            # Open the output file for writing
            with open(output_file, 'w') as outfile:
                # Process each line in the input file
                for line in infile:
                    # Split the line at '==' and take the first part (library name)
                    library_name = line.split('==')[0]
                    # Write the library name to the output file
                    outfile.write(library_name + '\n')
        print(f"Processed successfully. Output saved to {output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Define the input and output file paths
input_file = 'requirements.txt'  # Replace with the path to your input file
output_file = 'libraries.txt'  # Replace with the desired output file path

# Call the function to process the file
remove_versions(input_file, output_file)
