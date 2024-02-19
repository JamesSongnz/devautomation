import re
import sys

def remove_pattern_from_file(input_file, output_file):
    pattern = r'\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3} [IWDEV] \d+\s+\d+\s+'
    try:
        with open(input_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()
    except UnicodeDecodeError:
        print("Error: Unable to read the file with UTF-8 encoding. Trying with 'cp949' encoding...")
        with open(input_file, 'r', encoding='cp949') as file:
            lines = file.readlines()

    with open(output_file, 'w', encoding='utf-8') as file:
        for line in lines:
            modified_line = re.sub(pattern, '', line)
            file.write(modified_line)

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file + '.removed'
    remove_pattern_from_file(input_file, output_file)

if __name__ == "__main__":
    main()
