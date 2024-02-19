import re
import subprocess
import sys

def filter_lines(input_file, regex):
    with open(input_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    return [line for line in lines if re.match(regex, line)]

def write_output_file(input_file, regex, lines):
    safe_pattern = re.sub(r'[\\/*?:"<>|]', "_", regex)
    output_file = f"{input_file}.{safe_pattern}"
    with open(output_file, 'w', encoding='utf-8') as file:
        file.writelines(lines)
    return output_file

def main():
    if len(sys.argv) != 4:
        print("Usage: python script.py <inputfile1> <inputfile2> <regex>")
        sys.exit(1)

    input_file1, input_file2, regex = sys.argv[1], sys.argv[2], sys.argv[3]
    
    filtered_lines1 = filter_lines(input_file1, regex)
    filtered_lines2 = filter_lines(input_file2, regex)

    output_file1 = write_output_file(input_file1, regex, filtered_lines1)
    output_file2 = write_output_file(input_file2, regex, filtered_lines2)

    # WinMerge 실행 (WinMerge 경로가 정확해야 함)
    winmerge_path = "C:\\Program Files\\WinMerge\\WinMergeU.exe"
    subprocess.run([winmerge_path, output_file1, output_file2])

if __name__ == "__main__":
    main()
