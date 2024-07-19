import re
import subprocess
import os
import glob
import sys

# Global variable for the lower flash address
LOWER_FLASH_ADDRESS = 0x40000000

def extract_addresses(file_path):
    addresses = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            if "Guru Meditation Error" in line:
                # Extract the value after "PC: "
                pc_line = lines[i + 2]
                pc_match = re.search(r'PC\s*:\s*(0x[0-9a-fA-F]+)', pc_line)
                if pc_match:
                    pc_address = pc_match.group(1)
                    if int(pc_address, 16) >= LOWER_FLASH_ADDRESS:
                        addresses.append(pc_address)

                # Extract the values after "Backtrace:"
                for j in range(i, len(lines)):
                    if "Backtrace:" in lines[j]:
                        backtrace_line = lines[j]
                        backtrace_matches = re.findall(r'(0x[0-9a-fA-F]+)', backtrace_line)
                        for addr in backtrace_matches:
                            if int(addr, 16) >= LOWER_FLASH_ADDRESS:
                                addresses.append(addr)
                        break

    return addresses

def run_addr2line(addresses, firmware_path):
    results = []
    for addr in addresses:
        cmd = ["xtensa-esp32-elf-addr2line", "-pfiaC", "-e", firmware_path, addr]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            results.append(result.stdout.strip())
        except Exception as e:
            results.append(f"Error running addr2line for {addr}: {e}")
    return results

def process_files_in_directory(firmware_path):
    # Find all .txt files in the current directory
    txt_files = glob.glob("*.txt")

    for file_path in txt_files:
        # Extract addresses
        addresses = extract_addresses(file_path)

        if addresses:
            # Run addr2line command for each address
            results = run_addr2line(addresses, firmware_path)

            # Create output file path
            output_file_path = os.path.splitext(file_path)[0] + "_backtrace.txt"

            # Write results to the output file
            with open(output_file_path, 'w') as output_file:
                for result in results:
                    output_file.write(result + '\n')

            print(f"Results written to {output_file_path}")
        #else:
            #print(f"No valid addresses found in {file_path}, skipping output.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <firmware_path>")
        sys.exit(1)

    if sys.argv[1] == '--help':
        print("This Scritp automatize the search and Backtrace call debug for ESP\nIt looks for Expection in the txt files present in the current folder\n\nINPUT:(mandatory) is to give .elf file path as argument\n\nOUTPUT: txt file for each log where exception has been found\nit uses same name appending _backtrace")
        sys.exit(0)

    firmware_path = sys.argv[1]
    process_files_in_directory(firmware_path)
