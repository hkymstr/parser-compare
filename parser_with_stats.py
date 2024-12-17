import re
from pathlib import Path
import matplotlib.pyplot as plt


def get_last_2_bytes(hex_value):
    """
    Extract the last 2 bytes (4 hex digits) from a hex value.

    Args:
        hex_value (str): Hex value string (e.g., '0x1234ABCD')

    Returns:
        int: Integer value of the last 2 bytes
    """
    # Convert hex string to integer, handling both with and without '0x' prefix
    hex_str = hex_value.replace('0x', '').lower()
    full_int = int(hex_str, 16)
    # Mask to get last 2 bytes (0xFFFF = 65535 = 16 bits)
    last_2_bytes = full_int & 0xFFFF
    return last_2_bytes


def get_next_line_value(line):
    """
    Extract the comparison value from the next line based on its format.

    Args:
        line (str): The next line after a verify line

    Returns:
        str: The hex value to compare against, or None if not found
    """
    # First, try to find two hex values pattern (0x009739 0x0B)
    hex_matches = re.findall(r'0x[0-9a-fA-F]+', line)
    if len(hex_matches) >= 2:
        return hex_matches[1]

    # If not found, try to find 8-digit hex pattern (0000000a)
    hex_columns = line.split()
    for col in hex_columns:
        if len(col) == 8 and all(c in '0123456789abcdefABCDEF' for c in col):
            return '0x' + col

    return None


def parse_log_file(file_path):
    """
    Parse a log file to compare hex values between verify line and the following line.

    Args:
        file_path (str): Path to the log file

    Returns:
        list: List of dictionaries containing comparison results
    """
    results = []

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        for i in range(len(lines) - 1):
            current_line = lines[i].strip()
            next_line = lines[i + 1].strip()

            # Check for both verify formats
            verify_pattern = r'verify\s+(?:(?:\w+\s+is\s+)|(?:))0x[0-9a-fA-F]+\b'
            if re.search(verify_pattern, current_line, re.IGNORECASE):
                # Extract verify value
                verify_match = re.search(r'0x[0-9a-fA-F]+', current_line)
                if not verify_match:
                    continue

                verify_value = verify_match.group()
                next_value = get_next_line_value(next_line)

                if next_value:
                    # Compare values
                    verify_int = int(verify_value, 16)
                    next_last_2_bytes = get_last_2_bytes(next_value)
                    match_status = verify_int == next_last_2_bytes

                    results.append({
                        'line_number': i + 1,
                        'original_line': current_line,
                        'verify_value': verify_value,
                        'next_line': next_line,
                        'second_number': next_value,
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


def export_mismatches(results, output_file="mismatch.log"):
    """
    Export mismatched results to a log file.
    """
    try:
        with open(output_file, 'w') as f:
            f.write("Mismatch Log Report\n")
            f.write("==================\n\n")

            for result in results:
                if not result['match']:
                    f.write(f"Line Number: {result['line_number']}\n")
                    f.write(f"Original line: {result['original_line']}\n")
                    f.write(f"Verify value: {result['verify_value']}\n")
                    f.write(f"Next line: {result['next_line']}\n")
                    f.write(f"Second number: {result['second_number']}\n")
                    f.write(f"Second num last 2B: {result['last_2_bytes']}\n")
                    f.write("-" * 50 + "\n\n")

            print(f"\nMismatches have been exported to {output_file}")
    except Exception as e:
        print(f"Error writing to mismatch log: {str(e)}")


def calculate_statistics(results):
    """
    Calculate match/mismatch statistics from results.
    """
    total = len(results)
    matches = sum(1 for r in results if r['match'])
    mismatches = total - matches

    return {
        'total': total,
        'matches': matches,
        'mismatches': mismatches,
        'match_rate': (matches / total * 100) if total > 0 else 0
    }


def plot_results(stats):
    """
    Create a visualization of the results using matplotlib.
    Includes bar chart, pie chart, and statistics table.
    """
    # Create figure with gridspec for custom layout
    fig = plt.figure(figsize=(15, 6))
    gs = fig.add_gridspec(2, 3)

    # Bar plot
    ax1 = fig.add_subplot(gs[:, 0])
    categories = ['Matches', 'Mismatches']
    values = [stats['matches'], stats['mismatches']]
    bars = ax1.bar(categories, values, color=['green', 'red'])
    ax1.set_title('Match vs Mismatch Count')
    ax1.set_ylabel('Number of Comparisons')

    # Add value labels on top of bars
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width() / 2., height,
                 f'{int(height)}',
                 ha='center', va='bottom')

    # Pie chart
    ax2 = fig.add_subplot(gs[:, 1])
    labels = ['Matches', 'Mismatches']
    sizes = [stats['matches'], stats['mismatches']]
    colors = ['green', 'red']
    ax2.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax2.set_title('Match/Mismatch Distribution')

    # Statistics table
    ax3 = fig.add_subplot(gs[:, 2])
    ax3.axis('tight')
    ax3.axis('off')

    # Table data
    table_data = [
        ['Metric', 'Value'],
        ['Total Comparisons', stats['total']],
        ['Matches', stats['matches']],
        ['Mismatches', stats['mismatches']],
        ['Match Rate', f"{stats['match_rate']:.1f}%"]
    ]

    # Create table
    table = ax3.table(cellText=table_data,
                      loc='center',
                      cellLoc='left',
                      colWidths=[0.5, 0.3])

    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.2, 1.5)

    # Style header row
    for i in range(2):
        table[(0, i)].set_facecolor('#E6E6E6')
        table[(0, i)].set_text_props(weight='bold')

    plt.title('Statistics Summary', pad=20)
    plt.tight_layout()
    plt.show()


def display_results(results):
    """
    Display the results of the log file analysis.
    """
    if results:
        print("\nResults of log file analysis:")
        print("-" * 70)
        for result in results:
            match_status = "✓ MATCH" if result['match'] else "✗ MISMATCH"
            print(f"Line {result['line_number']}:")
            print(f"Original line:         {result['original_line']}")
            print(f"Verify value:          {result['verify_value']}")
            print(f"Next line:             {result['next_line']}")
            print(f"Second number:         {result['second_number']}")
            print(f"Second num last 2B:    {result['last_2_bytes']}")
            print(f"Status:                {match_status}")
            print("-" * 70)

        # Calculate and display statistics
        stats = calculate_statistics(results)
        print("\nSummary Statistics:")
        print(f"Total Comparisons:     {stats['total']}")
        print(f"Matches:              {stats['matches']}")
        print(f"Mismatches:           {stats['mismatches']}")
        print(f"Match Rate:           {stats['match_rate']:.1f}%")
        print("-" * 70)

        # Export mismatches if any exist
        if stats['mismatches'] > 0:
            export_mismatches(results)

        # Plot the results
        plot_results(stats)
    else:
        print("No verify lines found or error processing file")


def main():
    """
    Main function to run the log file parser.
    """
    log_file = input("Enter the path to your log file: ")
    results = parse_log_file(log_file)
    display_results(results)


if __name__ == '__main__':
    main()