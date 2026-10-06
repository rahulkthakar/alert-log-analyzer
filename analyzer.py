# import libraries
from pathlib import Path
import argparse

# parse command line arguments
parser = argparse.ArgumentParser(description='Find ORA errors in an alert log file.')
parser.add_argument('alert_log_file', type=str, help='Path to the alert log file')
args = parser.parse_args()
print(f"Alert log file: {args.alert_log_file}")
# create a function to find ora errors in a given alert log file
def find_ora_errors(alert_log_file):
    # check if the file exists
    if not Path(alert_log_file).is_file():
        print(f"Error: {alert_log_file} does not exist.")
        return

    # find ora errors in the alert log file
    errors = []
    for line in Path(alert_log_file).read_text().splitlines():
        if "ORA-" in line:
            errors.append(line.strip())
    return errors

# create a main function to read the alert log file and call the error finding function
def main():
    alert_log_file = args.alert_log_file
    errors = find_ora_errors(alert_log_file)
    if errors:
        print(f"Found {len(errors)} ORA errors in {alert_log_file}:")
        for error in errors:
            print(error)
    else:
        print(f"No ORA errors found in {alert_log_file}.")

# call main function if the script is run directly

if __name__ == "__main__":
    main()
    