import re
from pathlib import Path


def get_last_2_bytes(hex_value):
    """
    Extract the last 2 bytes (4 hex digits) from a hex value.

    Args:
        hex_value (str): Hex value string (e.g., '0x1234ABCD')

    Returns:
        int: Integer value of the last 2 bytes
    """
    # Convert hex string to integer
    full_int = int(hex_value, 16)
    # Mask to get last 2 bytes (0xFFFF = 65535 = 16 bits)
    last_2_bytes = full_int & 0xFFFF
    return last_2_bytes


def parse_log_file(file_path):
    """
    Parse a log file to compare hex values between verify line and the second number
    of the following line.

    Args:
        file_path (str): Path to the log file

    Returns:
        list: List of dictionaries containing line number, verify value, next line values, and match status
    """
    results = []

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        for i in range(len(lines) - 1):  # Stop one line before the end
            current_line = lines[i].strip()
            next_line = lines[i + 1].strip()

            # Check if current line contains 'verify'
            if 'verify' in current_line.lower():
                # Extract hex value from verify line
                verify_match = re.search(r'0x[0-9a-fA-F]+', current_line)
                # Extract all hex values from next line
                next_matches = re.findall(r'0x[0-9a-fA-F]+', next_line)

                if verify_match and len(next_matches) >= 2:  # Ensure we have at least 2 numbers
                    verify_value = verify_match.group()
                    next_value_second = next_matches[1]  # Get the second number

                    # Get the verify value and last 2 bytes of second number
                    verify_int = int(verify_value, 16)
                    next_last_2_bytes = get_last_2_bytes(next_value_second)

                    # Compare the verify value with the last 2 bytes of next value
                    match_status = verify_int == next_last_2_bytes

                    # Store all values in hex string format
                    results.append({
                        'line_number': i + 1,
                        'verify_value': verify_value,
                        'next_line': next_line,
                        'second_number': next_value_second,
                        'last_2_bytes': f"0x{next_last_2_bytes:04X}",
                        'match': match_status
                    })

    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        return []
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        return []

    return results


def display_results(results):
    """
    Display the results of the log file analysis in a formatted manner.

    Args:
        results (list): List of dictionaries containing comparison results
    """
    if results:
        print("\nResults of log file analysis:")
        print("-" * 70)
        for result in results:
            match_status = "✓ MATCH" if result['match'] else "✗ MISMATCH"
            print(f"Line {result['line_number']}:")
            print(f"Verify value:          {result['verify_value']}")
            print(f"Next line:             {result['next_line']}")
            print(f"Second number:         {result['second_number']}")
            print(f"Second num last 2B:    {result['last_2_bytes']}")
            print(f"Status:                {match_status}")
            print("-" * 70)
    else:
        print("No verify lines found or error processing file")


def main():
    """
    Main function to run the log file parser.
    """
    # Get the log file path from user input
    log_file = input("Enter the path to your log file: ")

    # Parse the log file
    results = parse_log_file(log_file)

    # Display the results
    display_results(results)


# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
