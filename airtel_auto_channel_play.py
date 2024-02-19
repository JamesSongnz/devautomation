import sys
import subprocess
import time

def read_file_and_execute_commands(file_path, start_channel):

    
    start_processing = False
    
    with open(file_path, 'r') as file:
        lines = file.readlines()
        
    current_index = 0
    if start_channel:
        for i, line in enumerate(lines):
            if line.strip() == start_channel:
                current_index = i
                break
            
    playing = []
    not_play = []
    
    while current_index < len(lines):
        line = lines[current_index]
        
        # 주석 처리된 라인 스킵
        if line.startswith("#"):
            current_index += 1
            continue
            
        channel_name = line.strip()
        url = f"http://192.168.0.12:8080/playAsset?asset=https://livea.streamready.in/{channel_name}/smil:common.smil/manifest.mpd"
        command = f"curl {url}"
        
        print(f"Executing: {command}")
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        print("Output:\n", stdout.decode())
        if stderr:
            print("Error:\n", stderr.decode())

        # 채널 이름과 함께 구분선 출력을 3번 반복
        separator = f"============== {channel_name} =========="
        for _ in range(3):
            print(separator)
            
        time.sleep(2)

        user_input = input("Enter 'ok' to play, 'f' to fail, 'p' to go to the previous channel: ")
        if user_input.lower() == 'ok':
            if channel_name not in playing:
                playing.append(channel_name)
        elif user_input.lower() == 'f':
            if channel_name not in not_play:
                not_play.append(channel_name)
        elif user_input.lower() == 'p':
            current_index = max(0, current_index - 1)
            continue
        else:
            break

        current_index += 1
        
    # After the loop, you can print or process the lists as needed
    print("\n=======Playing list:\n", playing)
    print("\n\n === Not playing list:\n", not_play)

if __name__ == "__main__":
    file_path = 'airtel_channels.txt'  # 데이터 파일 경로를 여기에 입력하세요.
    start_channel = sys.argv[1] if len(sys.argv) > 1 else ""
#    start_channel = input("Enter the channel name to start from (leave blank to start from the beginning): ").strip()
    read_file_and_execute_commands(file_path, start_channel)
