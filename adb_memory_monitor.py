import subprocess
import re
import time
import os
import pprint

def parse_meminfo_output(dumpsys_output):
    """
    Parses the output of 'adb shell dumpsys meminfo' command.
    Returns a dictionary with process name as key and memory usage details as value.
    """

    print("Parsing meminfo output...")
    # Regular expression to extract memory usage, process name, and pid
    # Updated to exclude sections that should not be tracked

    
    # Regular expression to extract memory usage, process name, and pid
    process_memory_pattern = r"Total (RSS|PSS) by process:\s*\n(.*?)\n(?=Total)"
    
    memory_data = {}
    # Using re.finditer to apply the regex to the string and process each section
    matches = re.finditer(process_memory_pattern, dumpsys_output, re.DOTALL)
    for match in matches:
        memory_type = match.group(1)  # RSS or PSS
        processes = match.group(2)

        # Process each line in the current section
        process_lines = processes.strip().split('\n')
        for line in process_lines:
            match = re.search(r"([\d,]+)K: (.+) \(pid (\d+)(?: / .+)?\)", line)
            
            if match:
                memory_usage_str, process_name, pid = match.groups()
                memory_usage = int(memory_usage_str.replace(',', ''))
                pid = int(pid)
            
                # Construct a unique key as 'process_name-pid'
                process_key = f"{process_name}-{pid}"

                # Initialize or update the dictionary for the process
                memory_data.setdefault(process_key, {"RSS": None, "PSS": None, "pid": pid})
                memory_data[process_key][memory_type] = memory_usage


                #print(f"Memory Type: {memory_type}, Memory Usage: {memory_usage}, Process Name: {process_name}, PID: {pid}")
  

    # Adjusted pattern to correctly match multiline RAM statistics
    ram_stats_pattern = r"\s*Total RAM:\s+([\d,]+)K.*\n\s*Free RAM:\s+([\d,]+)K.*\n.*Used RAM:\s+([\d,]+)K.*\n\s*Lost RAM:\s+([\d,]+)K"
    
    # Find RAM statistics
    ram_stats_match = re.search(ram_stats_pattern, dumpsys_output, re.DOTALL)
    if ram_stats_match:
        total_ram_str, free_ram_str, used_ram_str, lost_ram_str = ram_stats_match.groups()
        total_ram = int(total_ram_str.replace(',', ''))
        free_ram = int(free_ram_str.replace(',', ''))
        used_ram = int(used_ram_str.replace(',', ''))
        lost_ram = int(lost_ram_str.replace(',', ''))
        memory_data["RAM_Stats"] = {"Total_RAM": total_ram, "Free_RAM": free_ram, "Used_RAM": used_ram, "Lost_RAM": lost_ram}
    else:
        print("not matched ram stat")
        exit(1)

    return memory_data

def track_memory_changes(current_data, previous_data):
    """
    Compares the current memory data with the previous data to track changes.
    Adjusted to handle the new data structure with 'RSS' and 'PSS'.
    Returns a dictionary with the changes.
    """
    print("Tracking memory changes...")
    changes = {}
    for process_key, current_info in current_data.items():
        if process_key in previous_data:
            # Iterate through both RSS and PSS for changes
            for mem_type in ['RSS', 'PSS']:
                if mem_type in current_info and mem_type in previous_data[process_key]:
                    current_memory = current_info[mem_type]
                    previous_memory = previous_data[process_key][mem_type]

                    # Check if there is a change in memory usage
                    if current_memory is not None and previous_memory is not None and current_memory != previous_memory:
                        memory_diff = current_memory - previous_memory
                        change_key = f"{process_key} ({mem_type})"
                        changes[change_key] = memory_diff
        else:
            changes[process_key] = current_info


    # Track changes in RAM statistics
    if "RAM_Stats" in current_data and "RAM_Stats" in previous_data:
        for stat_key, current_stat in current_data["RAM_Stats"].items():
            if stat_key in previous_data["RAM_Stats"]:
                previous_stat = previous_data["RAM_Stats"][stat_key]
                if current_stat != previous_stat:
                    stat_diff = current_stat - previous_stat
                    changes[f"RAM_Stats {stat_key}"] = stat_diff
                    print( f"changes for RAM : {changes[f'RAM_Stats {stat_key}']}  = {stat_diff}")


    for process_key in previous_data:
        if process_key not in current_data:
            changes[process_key] = "Process Ended"

    # Sort the changes by the magnitude of change
    #sorted_changes = {k: v for k, v in sorted(changes.items(), key=lambda item: abs(item[1]), reverse=True)}
    #sorted_changes = {k: v for k, v in sorted(changes.items(), key=lambda item: (isinstance(item[1], int), abs(item[1]) if isinstance(item[1], int) else item[1]), reverse=True)}
    sorted_changes = {
        k: v for k, v in sorted(changes.items(), key=lambda item: (isinstance(item[1], int), abs(item[1]) if isinstance(item[1], int) else float('inf')), reverse=True)
    }

    return sorted_changes

def log_memory_changes(changes, current_data, initial_data, file_path):
    """
    Logs the memory changes to a file, adjusted for the new data structure.
    """
    ram_stat_changes = {}
    with open(file_path, "a") as file:
        for process_key, change in changes.items():
            if process_key.startswith("RAM_Stats"):
                # Store RAM stats changes for later processing
                ram_stat_changes[process_key] = change
                continue
            
            if isinstance(change, int):
                # Extract memory type (RSS or PSS) from the key
                memory_type = process_key.split()[-1].strip('()')  # Extracts 'RSS' or 'PSS'

                # Construct the original process key without memory type
                original_key = process_key.rsplit(' (', 1)[0]

                # Get initial and current memory values
                initial_memory = initial_data.get(original_key, {}).get(memory_type, 0)
                current_memory = current_data.get(original_key, {}).get(memory_type, 0)

                # Calculate differences
                initial_diff = current_memory - initial_memory
                change_str = f"Memory change: {'+' if change > 0 else ''}{change:,}K"
                initial_diff_str = f"FromInitial: {'+' if initial_diff > 0 else ''}{initial_diff:,}K"
                current_memory_str = f"Current: {current_memory:,}K"

                log_entry = f"{process_key:<40}: {current_memory_str:<20}  {change_str:<20}  {initial_diff_str:<20}\n"
            else:
                # For non-integer changes like "New Process" or "Process Ended"
                change_str = change
                log_entry = f"{process_key}: {change_str}\n"


            print(log_entry, end="")  # Print to console
            file.write(log_entry)     # Write to file

        # Log RAM stats changes
        print(" -Device RAM_Stats:: --\n")
        
        for stat_key, current_stat in current_data["RAM_Stats"].items():

                init_stat = initial_data["RAM_Stats"][stat_key]
                initial_diff = current_stat - init_stat
                
                change_key = f"RAM_Stats {stat_key}"
                if change_key not in changes:
                    continue  # Skip this stat if change is not recorded
                           
                change = changes[change_key]                           
                change_str = f"{current_stat:,}K (Change: {'+' if change > 0 else ''}{change:,}K)"
                initial_str = f" (Initial: {'+' if initial_diff > 0 else ''}{initial_diff:,}K)"
                ram_stat_log = f"{stat_key}: {change_str}  {initial_str}\n"
                print(ram_stat_log, end="")  # Print to console
                file.write(ram_stat_log)     # Write to file

        """                                        
        for stat_key, change in ram_stat_changes.items():
            print(f"stat_key, change : {stat_key}, {change}")
            stat_name = stat_key.split()[-1]  # Extract stat name
            current_value = current_data["RAM_Stats"].get(stat_name, 0)
            initial_value = initial_data["RAM_Stats"].get(stat_name, 0)
            initial_diff = current_value - initial_value

            change_str = f"{current_value}K (Change: {'+' if change > 0 else ''}{change}K)"
            initial_str = f" (Initial: {'+' if initial_diff > 0 else ''}{initial_diff}K)"
            ram_stat_log = f"{stat_key}: {change_str}  {initial_str}\n"
            print(ram_stat_log, end="")  # Print to console
            file.write(ram_stat_log)     # Write to file
        """

def main():
    previous_data = {}
    initial_data = None  # Initialize the initial_data
    log_file = "memory_tracking_log.txt"


    while True:
        try:
            # Execute adb command and get output
            output = subprocess.check_output("adb shell dumpsys meminfo", shell=True).decode('utf-8', 'ignore')

    
            # Replace all non-ASCII characters with a space and convert tabs to spaces
            
            dumpsys_output = output.replace('\t', ' ')  # Replace tabs with spaces
  
                        
            # Parse the output
            current_data = parse_meminfo_output(dumpsys_output)

            # Initialize initial_data if it's not set
            if initial_data is None:
                initial_data = current_data.copy()
                # Using pprint for a formatted output
                pprint.pprint(current_data)
                
            # Track changes
            changes = track_memory_changes(current_data, previous_data)

            # Log and print changes
            log_memory_changes(changes, current_data, initial_data, log_file)

   
            print("----\n")
            # Update previous data for next iteration
            previous_data = current_data

            # Wait for 5 seconds before next execution
            time.sleep(5)
        
        except subprocess.CalledProcessError as e:
            print(f"Failed to execute adb command: {e}")
            break


# Sample output for demonstration
test_dumpsys_output = """
Applications Memory Usage (in Kilobytes):
Uptime: 7963316 Realtime: 7963316


Total RSS by process:
    218,484K: system (pid 602)
    207,884K: com.google.android.gms.persistent (pid 8997)
    187,792K: com.google.android.backdrop (pid 6148 / activities)
    165,776K: com.google.android.gms (pid 9566)
    141,188K: com.google.android.katniss:interactor (pid 8401)
    128,108K: com.android.vending (pid 8746)
    116,692K: com.google.android.katniss:search (pid 8557)
    103,592K: com.google.android.videos (pid 9264)
     93,964K: com.google.android.apps.mediashell (pid 7155)
     90,052K: com.google.android.tvrecommendations (pid 8658)
     84,556K: com.android.vending:background (pid 5273)
     83,480K: com.google.android.tvlauncher (pid 9665)
     80,196K: com.google.android.tv.remote.service (pid 8227)
     79,804K: com.google.android.webview:sandboxed_process0:org.chromium.content.app.SandboxedProcessService0:0 (pid 6177)
     77,004K: android.process.acore (pid 8312)
     66,504K: com.google.process.gapps (pid 8090)
     64,648K: android.process.media (pid 8873)
     63,104K: com.google.android.tungsten.setupwraith (pid 7795)
     61,696K: com.android.systemui (pid 787)
     56,936K: com.google.android.permissioncontroller (pid 2548)
     55,312K: com.android.bluetooth (pid 770)
     54,648K: com.google.android.syncadapters.calendar (pid 7708)
     53,864K: com.android.vending:instant_app_installer (pid 5079)
     53,796K: com.google.process.gservices (pid 1426)
     52,360K: com.android.providers.media.module (pid 1445)
     51,780K: com.android.providers.tv (pid 1785)
     50,964K: com.droidlogic.mictoggle (pid 1591)
     49,560K: zygote (pid 348)
     49,120K: com.google.android.ext.services (pid 1009)
     47,776K: com.android.keychain (pid 6761)
     43,520K: com.droidlogic (pid 904)
     41,332K: com.android.se (pid 947)
     40,008K: webview_zygote (pid 5868)
     16,292K: android.hardware.audio.service-droidlogic (pid 371)
     11,428K: surfaceflinger (pid 433)
      7,632K: audioserver (pid 424)
      7,048K: keystore2 (pid 277)
      6,316K: android.hardware.drm@1.4-service.widevine (pid 378)
      5,920K: statsd (pid 346)
      5,884K: adbd (pid 515)
      5,580K: android.hardware.camera.provider@2.5-service (pid 373)
      5,276K: android.hardware.graphics.composer@2.4-service.droidlogic (pid 383)
      5,128K: wpa_supplicant (pid 1180)
      5,124K: media.extractor (pid 479)
      5,096K: netd (pid 347)
      4,996K: mediaserver (pid 481)
      4,708K: media.codec (pid 489)
      4,184K: installd (pid 476)
      4,160K: logd (pid 233)
      4,128K: android.hardware.security.keymint-service.amlogic (pid 282)
      4,072K: android.hardware.oemlock-service.droidlogic (pid 387)
      4,024K: android.hardware.drm@1.4-service.nagra (pid 4470)
      3,968K: subtitleserver (pid 419)
      3,960K: android.hardware.graphics.allocator@4.0-service (pid 382)
      3,944K: android.hardware.drm@1.4-service.clearkey (pid 375)
      3,924K: android.hardware.drm@1.4-service.playready (pid 377)
      3,916K: wificond (pid 488)
      3,860K: android.hardware.bluetooth@1.0-service-droidlogic (pid 372)
      3,844K: systemcontrol (pid 369)
      3,812K: android.hardware.wifi@1.0-service.droidlogic (pid 405)
      3,808K: android.hardware.tv.cec@1.0-service (pid 397)
      3,744K: cameraserver (pid 469)
      3,740K: init (pid 1)
      3,720K: android.hardware.cas@1.2-service (pid 374)
      3,716K: media.swcodec (pid 491)
      3,656K: media.metrics (pid 480)
      3,584K: android.hardware.oemlock@1.0-service.droidlogic (pid 389)
      3,576K: android.hardware.health@2.1-service.droidlogic (pid 385)
      3,556K: android.hardware.thermal@2.0-service.droidlogic (pid 394)
      3,544K: hwservicemanager (pid 236)
      3,532K: vold (pid 253)
      3,488K: media.tuner (pid 482)
      3,476K: ueventd (pid 222)
      3,388K: android.hardware.ir@1.0-service (pid 386)
      3,388K: android.hardware.usb@1.0-service (pid 402)
      3,380K: android.hardware.boot@1.2-service.droidlogic (pid 281)
      3,340K: android.hardware.gatekeeper@1.0-service.software (pid 380)
      3,332K: android.hardware.usb.gadget@1.2-service.droidlogic (pid 398)
      3,324K: llkd (pid 501)
      3,240K: android.hardware.atrace@1.0-service (pid 278)
      3,212K: android.hardware.power.aidl-service.droidlogic (pid 391)
      3,156K: update_engine (pid 494)
      3,088K: android.hardware.memtrack-service.droidlogic (pid 415)
      3,088K: dumpsys (pid 9832)
      3,040K: gatekeeperd (pid 493)
      3,008K: servicemanager (pid 235)
      2,996K: lmkd (pid 234)
      2,992K: lights (pid 414)
      2,960K: credstore (pid 429)
      2,956K: storaged (pid 483)
      2,848K: android.system.suspend@1.0-service (pid 276)
      2,796K: hdcp_tx22 (pid 580)
      2,700K: gpuservice (pid 431)
      2,472K: incidentd (pid 473)
      2,428K: drmserver (pid 453)
      2,308K: android.hidl.allocator@1.0-service (pid 370)
      2,308K: logcat (pid 2461)
      2,280K: tee-supplicant (pid 252)
      2,176K: iptables-restore (pid 352)
      2,176K: ip6tables-restore (pid 353)
      2,060K: traced (pid 460)
      1,980K: traced_probes (pid 458)
      1,824K: init (pid 220)
      1,792K: tombstoned (pid 315)
      1,772K: sh (pid 330)
        484K: mdnsd (pid 536)

Total RSS by OOM adjustment:
    373,224K: Native
         49,560K: zygote (pid 348)
         40,008K: webview_zygote (pid 5868)
         16,292K: android.hardware.audio.service-droidlogic (pid 371)
         11,428K: surfaceflinger (pid 433)
          7,632K: audioserver (pid 424)
          7,048K: keystore2 (pid 277)
          6,316K: android.hardware.drm@1.4-service.widevine (pid 378)
          5,920K: statsd (pid 346)
          5,884K: adbd (pid 515)
          5,580K: android.hardware.camera.provider@2.5-service (pid 373)
          5,276K: android.hardware.graphics.composer@2.4-service.droidlogic (pid 383)
          5,128K: wpa_supplicant (pid 1180)
          5,124K: media.extractor (pid 479)
          5,096K: netd (pid 347)
          4,996K: mediaserver (pid 481)
          4,708K: media.codec (pid 489)
          4,184K: installd (pid 476)
          4,160K: logd (pid 233)
          4,128K: android.hardware.security.keymint-service.amlogic (pid 282)
          4,072K: android.hardware.oemlock-service.droidlogic (pid 387)
          4,024K: android.hardware.drm@1.4-service.nagra (pid 4470)
          3,968K: subtitleserver (pid 419)
          3,960K: android.hardware.graphics.allocator@4.0-service (pid 382)
          3,944K: android.hardware.drm@1.4-service.clearkey (pid 375)
          3,924K: android.hardware.drm@1.4-service.playready (pid 377)
          3,916K: wificond (pid 488)
          3,860K: android.hardware.bluetooth@1.0-service-droidlogic (pid 372)
          3,844K: systemcontrol (pid 369)
          3,812K: android.hardware.wifi@1.0-service.droidlogic (pid 405)
          3,808K: android.hardware.tv.cec@1.0-service (pid 397)
          3,744K: cameraserver (pid 469)
          3,740K: init (pid 1)
          3,720K: android.hardware.cas@1.2-service (pid 374)
          3,716K: media.swcodec (pid 491)
          3,656K: media.metrics (pid 480)
          3,584K: android.hardware.oemlock@1.0-service.droidlogic (pid 389)
          3,576K: android.hardware.health@2.1-service.droidlogic (pid 385)
          3,556K: android.hardware.thermal@2.0-service.droidlogic (pid 394)
          3,544K: hwservicemanager (pid 236)
          3,532K: vold (pid 253)
          3,488K: media.tuner (pid 482)
          3,476K: ueventd (pid 222)
          3,388K: android.hardware.ir@1.0-service (pid 386)
          3,388K: android.hardware.usb@1.0-service (pid 402)
          3,380K: android.hardware.boot@1.2-service.droidlogic (pid 281)
          3,340K: android.hardware.gatekeeper@1.0-service.software (pid 380)
          3,332K: android.hardware.usb.gadget@1.2-service.droidlogic (pid 398)
          3,324K: llkd (pid 501)
          3,240K: android.hardware.atrace@1.0-service (pid 278)
          3,212K: android.hardware.power.aidl-service.droidlogic (pid 391)
          3,156K: update_engine (pid 494)
          3,088K: android.hardware.memtrack-service.droidlogic (pid 415)
          3,088K: dumpsys (pid 9832)
          3,040K: gatekeeperd (pid 493)
          3,008K: servicemanager (pid 235)
          2,996K: lmkd (pid 234)
          2,992K: lights (pid 414)
          2,960K: credstore (pid 429)
          2,956K: storaged (pid 483)
          2,848K: android.system.suspend@1.0-service (pid 276)
          2,796K: hdcp_tx22 (pid 580)
          2,700K: gpuservice (pid 431)
          2,472K: incidentd (pid 473)
          2,428K: drmserver (pid 453)
          2,308K: android.hidl.allocator@1.0-service (pid 370)
          2,308K: logcat (pid 2461)
          2,280K: tee-supplicant (pid 252)
          2,176K: iptables-restore (pid 352)
          2,176K: ip6tables-restore (pid 353)
          2,060K: traced (pid 460)
          1,980K: traced_probes (pid 458)
          1,824K: init (pid 220)
          1,792K: tombstoned (pid 315)
          1,772K: sh (pid 330)
            484K: mdnsd (pid 536)
    218,484K: System
        218,484K: system (pid 602)
    146,548K: Persistent
         61,696K: com.android.systemui (pid 787)
         43,520K: com.droidlogic (pid 904)
         41,332K: com.android.se (pid 947)
    107,672K: Persistent Service
         55,312K: com.android.bluetooth (pid 770)
         52,360K: com.android.providers.media.module (pid 1445)
    267,596K: Foreground
        187,792K: com.google.android.backdrop (pid 6148 / activities)
         79,804K: com.google.android.webview:sandboxed_process0:org.chromium.content.app.SandboxedProcessService0:0 (pid 6177)
    623,316K: Visible
        207,884K: com.google.android.gms.persistent (pid 8997)
        141,188K: com.google.android.katniss:interactor (pid 8401)
         93,964K: com.google.android.apps.mediashell (pid 7155)
         80,196K: com.google.android.tv.remote.service (pid 8227)
         50,964K: com.droidlogic.mictoggle (pid 1591)
         49,120K: com.google.android.ext.services (pid 1009)
     90,052K: Perceptible Medium
         90,052K: com.google.android.tvrecommendations (pid 8658)
  1,272,264K: Cached
        165,776K: com.google.android.gms (pid 9566)
        128,108K: com.android.vending (pid 8746)
        116,692K: com.google.android.katniss:search (pid 8557)
        103,592K: com.google.android.videos (pid 9264)
         84,556K: com.android.vending:background (pid 5273)
         83,480K: com.google.android.tvlauncher (pid 9665)
         77,004K: android.process.acore (pid 8312)
         66,504K: com.google.process.gapps (pid 8090)
         64,648K: android.process.media (pid 8873)
         63,104K: com.google.android.tungsten.setupwraith (pid 7795)
         56,936K: com.google.android.permissioncontroller (pid 2548)
         54,648K: com.google.android.syncadapters.calendar (pid 7708)
         53,864K: com.android.vending:instant_app_installer (pid 5079)
         53,796K: com.google.process.gservices (pid 1426)
         51,780K: com.android.providers.tv (pid 1785)
         47,776K: com.android.keychain (pid 6761)

Total RSS by category:
    688,560K: .so mmap
    566,600K: .jar mmap
    357,456K: .art mmap
    294,756K: .apk mmap
    285,524K: .oat mmap
    251,860K: Dalvik
    175,392K: .dex mmap
    149,316K: Native
     93,300K: GL mtrack
     77,864K: Other mmap
     70,236K: Dalvik Other
     30,048K: Unknown
     24,112K: Other dev
     17,720K: Ashmem
     16,204K: Stack
        208K: .ttf mmap
          0K: Cursor
          0K: Gfx dev
          0K: EGL mtrack
          0K: Other mtrack

Total PSS by process:
    146,991K: com.google.android.backdrop (pid 6148 / activities)
    109,364K: system (pid 602)
     93,101K: com.google.android.gms.persistent (pid 8997)
     68,314K: com.google.android.gms (pid 9566)
     61,933K: com.android.vending (pid 8746)
     56,315K: com.google.android.katniss:interactor (pid 8401)
     48,175K: com.google.android.apps.mediashell (pid 7155)
     40,141K: com.google.android.videos (pid 9264)
     35,340K: com.google.android.katniss:search (pid 8557)
     32,620K: com.android.vending:background (pid 5273)
     31,217K: com.google.android.webview:sandboxed_process0:org.chromium.content.app.SandboxedProcessService0:0 (pid 6177)
     27,991K: com.google.android.tvlauncher (pid 9665)
     22,894K: com.google.android.tvrecommendations (pid 8658)
     22,259K: com.android.systemui (pid 787)
     19,440K: surfaceflinger (pid 433)
     19,429K: com.google.android.tungsten.setupwraith (pid 7795)
     19,118K: android.process.acore (pid 8312)
     17,370K: com.android.vending:instant_app_installer (pid 5079)
     16,128K: com.google.android.permissioncontroller (pid 2548)
     15,990K: com.android.bluetooth (pid 770)
     15,508K: com.google.android.tv.remote.service (pid 8227)
     14,896K: com.google.process.gapps (pid 8090)
     14,344K: com.android.providers.media.module (pid 1445)
     14,286K: android.process.media (pid 8873)
     14,040K: com.google.process.gservices (pid 1426)
     13,886K: com.google.android.syncadapters.calendar (pid 7708)
     13,476K: com.android.providers.tv (pid 1785)
     12,709K: com.android.keychain (pid 6761)
     12,297K: com.droidlogic.mictoggle (pid 1591)
     11,355K: android.hardware.audio.service-droidlogic (pid 371)
     10,374K: zygote (pid 348)
     10,022K: com.google.android.ext.services (pid 1009)
      8,958K: com.droidlogic (pid 904)
      7,761K: com.android.se (pid 947)
      6,550K: webview_zygote (pid 5868)
      6,207K: audioserver (pid 424)
      5,353K: media.extractor (pid 479)
      5,348K: media.codec (pid 489)
      4,647K: mediaserver (pid 481)
      4,154K: statsd (pid 346)
      4,040K: keystore2 (pid 277)
      3,952K: init (pid 1)
      3,701K: media.swcodec (pid 491)
      3,607K: adbd (pid 515)
      3,588K: android.hardware.camera.provider@2.5-service (pid 373)
      3,355K: cameraserver (pid 469)
      3,228K: media.metrics (pid 480)
      3,219K: logd (pid 233)
      3,194K: android.hardware.drm@1.4-service.widevine (pid 378)
      2,940K: systemcontrol (pid 369)
      2,678K: netd (pid 347)
      2,555K: ueventd (pid 222)
      2,486K: android.hardware.graphics.composer@2.4-service.droidlogic (pid 383)
      2,346K: wpa_supplicant (pid 1180)
      2,106K: media.tuner (pid 482)
      1,865K: installd (pid 476)
      1,833K: vold (pid 253)
      1,786K: wificond (pid 488)
      1,701K: init (pid 220)
      1,330K: hwservicemanager (pid 236)
      1,319K: update_engine (pid 494)
      1,305K: android.hardware.graphics.allocator@4.0-service (pid 382)
      1,275K: android.hardware.wifi@1.0-service.droidlogic (pid 405)
      1,262K: llkd (pid 501)
      1,241K: subtitleserver (pid 419)
      1,225K: android.hardware.bluetooth@1.0-service-droidlogic (pid 372)
      1,181K: android.hardware.security.keymint-service.amlogic (pid 282)
      1,173K: android.hardware.drm@1.4-service.playready (pid 377)
      1,165K: gpuservice (pid 431)
      1,120K: android.hardware.drm@1.4-service.nagra (pid 4470)
      1,120K: servicemanager (pid 235)
      1,076K: storaged (pid 483)
      1,016K: android.hardware.drm@1.4-service.clearkey (pid 375)
        951K: iptables-restore (pid 352)
        951K: ip6tables-restore (pid 353)
        904K: drmserver (pid 453)
        890K: credstore (pid 429)
        883K: android.system.suspend@1.0-service (pid 276)
        881K: android.hardware.oemlock-service.droidlogic (pid 387)
        859K: android.hardware.cas@1.2-service (pid 374)
        853K: android.hardware.tv.cec@1.0-service (pid 397)
        815K: logcat (pid 2461)
        801K: android.hardware.thermal@2.0-service.droidlogic (pid 394)
        789K: android.hardware.oemlock@1.0-service.droidlogic (pid 389)
        789K: gatekeeperd (pid 493)
        781K: android.hardware.boot@1.2-service.droidlogic (pid 281)
        775K: incidentd (pid 473)
        773K: android.hardware.health@2.1-service.droidlogic (pid 385)
        773K: traced (pid 460)
        745K: android.hardware.power.aidl-service.droidlogic (pid 391)
        717K: android.hardware.gatekeeper@1.0-service.software (pid 380)
        716K: android.hardware.usb.gadget@1.2-service.droidlogic (pid 398)
        700K: android.hardware.usb@1.0-service (pid 402)
        689K: android.hardware.ir@1.0-service (pid 386)
        675K: android.hardware.memtrack-service.droidlogic (pid 415)
        656K: dumpsys (pid 9832)
        649K: lmkd (pid 234)
        646K: android.hardware.atrace@1.0-service (pid 278)
        629K: lights (pid 414)
        599K: sh (pid 330)
        596K: hdcp_tx22 (pid 580)
        594K: android.hidl.allocator@1.0-service (pid 370)
        585K: traced_probes (pid 458)
        572K: mdnsd (pid 536)
        509K: tee-supplicant (pid 252)
        442K: tombstoned (pid 315)

Total PSS by OOM adjustment:
    168,603K: Native
         19,440K: surfaceflinger (pid 433)
         11,355K: android.hardware.audio.service-droidlogic (pid 371)
         10,374K: zygote (pid 348)
          6,550K: webview_zygote (pid 5868)
          6,207K: audioserver (pid 424)
          5,353K: media.extractor (pid 479)
          5,348K: media.codec (pid 489)
          4,647K: mediaserver (pid 481)
          4,154K: statsd (pid 346)
          4,040K: keystore2 (pid 277)
          3,952K: init (pid 1)
          3,701K: media.swcodec (pid 491)
          3,607K: adbd (pid 515)
          3,588K: android.hardware.camera.provider@2.5-service (pid 373)
          3,355K: cameraserver (pid 469)
          3,228K: media.metrics (pid 480)
          3,219K: logd (pid 233)
          3,194K: android.hardware.drm@1.4-service.widevine (pid 378)
          2,940K: systemcontrol (pid 369)
          2,678K: netd (pid 347)
          2,555K: ueventd (pid 222)
          2,486K: android.hardware.graphics.composer@2.4-service.droidlogic (pid 383)
          2,346K: wpa_supplicant (pid 1180)
          2,106K: media.tuner (pid 482)
          1,865K: installd (pid 476)
          1,833K: vold (pid 253)
          1,786K: wificond (pid 488)
          1,701K: init (pid 220)
          1,330K: hwservicemanager (pid 236)
          1,319K: update_engine (pid 494)
          1,305K: android.hardware.graphics.allocator@4.0-service (pid 382)
          1,275K: android.hardware.wifi@1.0-service.droidlogic (pid 405)
          1,262K: llkd (pid 501)
          1,241K: subtitleserver (pid 419)
          1,225K: android.hardware.bluetooth@1.0-service-droidlogic (pid 372)
          1,181K: android.hardware.security.keymint-service.amlogic (pid 282)
          1,173K: android.hardware.drm@1.4-service.playready (pid 377)
          1,165K: gpuservice (pid 431)
          1,120K: android.hardware.drm@1.4-service.nagra (pid 4470)
          1,120K: servicemanager (pid 235)
          1,076K: storaged (pid 483)
          1,016K: android.hardware.drm@1.4-service.clearkey (pid 375)
            951K: iptables-restore (pid 352)
            951K: ip6tables-restore (pid 353)
            904K: drmserver (pid 453)
            890K: credstore (pid 429)
            883K: android.system.suspend@1.0-service (pid 276)
            881K: android.hardware.oemlock-service.droidlogic (pid 387)
            859K: android.hardware.cas@1.2-service (pid 374)
            853K: android.hardware.tv.cec@1.0-service (pid 397)
            815K: logcat (pid 2461)
            801K: android.hardware.thermal@2.0-service.droidlogic (pid 394)
            789K: android.hardware.oemlock@1.0-service.droidlogic (pid 389)
            789K: gatekeeperd (pid 493)
            781K: android.hardware.boot@1.2-service.droidlogic (pid 281)
            775K: incidentd (pid 473)
            773K: android.hardware.health@2.1-service.droidlogic (pid 385)
            773K: traced (pid 460)
            745K: android.hardware.power.aidl-service.droidlogic (pid 391)
            717K: android.hardware.gatekeeper@1.0-service.software (pid 380)
            716K: android.hardware.usb.gadget@1.2-service.droidlogic (pid 398)
            700K: android.hardware.usb@1.0-service (pid 402)
            689K: android.hardware.ir@1.0-service (pid 386)
            675K: android.hardware.memtrack-service.droidlogic (pid 415)
            656K: dumpsys (pid 9832)
            649K: lmkd (pid 234)
            646K: android.hardware.atrace@1.0-service (pid 278)
            629K: lights (pid 414)
            599K: sh (pid 330)
            596K: hdcp_tx22 (pid 580)
            594K: android.hidl.allocator@1.0-service (pid 370)
            585K: traced_probes (pid 458)
            572K: mdnsd (pid 536)
            509K: tee-supplicant (pid 252)
            442K: tombstoned (pid 315)
    109,364K: System
        109,364K: system (pid 602)
     38,978K: Persistent
         22,259K: com.android.systemui (pid 787)
          8,958K: com.droidlogic (pid 904)
          7,761K: com.android.se (pid 947)
     30,334K: Persistent Service
         15,990K: com.android.bluetooth (pid 770)
         14,344K: com.android.providers.media.module (pid 1445)
    178,208K: Foreground
        146,991K: com.google.android.backdrop (pid 6148 / activities)
         31,217K: com.google.android.webview:sandboxed_process0:org.chromium.content.app.SandboxedProcessService0:0 (pid 6177)
    235,418K: Visible
         93,101K: com.google.android.gms.persistent (pid 8997)
         56,315K: com.google.android.katniss:interactor (pid 8401)
         48,175K: com.google.android.apps.mediashell (pid 7155)
         15,508K: com.google.android.tv.remote.service (pid 8227)
         12,297K: com.droidlogic.mictoggle (pid 1591)
         10,022K: com.google.android.ext.services (pid 1009)
     22,894K: Perceptible Medium
         22,894K: com.google.android.tvrecommendations (pid 8658)
    421,677K: Cached
         68,314K: com.google.android.gms (pid 9566)
         61,933K: com.android.vending (pid 8746)
         40,141K: com.google.android.videos (pid 9264)
         35,340K: com.google.android.katniss:search (pid 8557)
         32,620K: com.android.vending:background (pid 5273)
         27,991K: com.google.android.tvlauncher (pid 9665)
         19,429K: com.google.android.tungsten.setupwraith (pid 7795)
         19,118K: android.process.acore (pid 8312)
         17,370K: com.android.vending:instant_app_installer (pid 5079)
         16,128K: com.google.android.permissioncontroller (pid 2548)
         14,896K: com.google.process.gapps (pid 8090)
         14,286K: android.process.media (pid 8873)
         14,040K: com.google.process.gservices (pid 1426)
         13,886K: com.google.android.syncadapters.calendar (pid 7708)
         13,476K: com.android.providers.tv (pid 1785)
         12,709K: com.android.keychain (pid 6761)

Total PSS by category:
    192,463K: Dalvik
    147,654K: .apk mmap
    124,966K: Native
    105,823K: .dex mmap
     93,300K: GL mtrack
     80,064K: .so mmap
     59,243K: .art mmap
     39,549K: .jar mmap
     35,367K: Dalvik Other
     22,185K: Unknown
     16,072K: Stack
     12,009K: Other mmap
     11,943K: .oat mmap
        919K: Other dev
        820K: Ashmem
        208K: .ttf mmap
          0K: Cursor
          0K: Gfx dev
          0K: EGL mtrack
          0K: Other mtrack

Total RAM: 2,036,984K (status normal)
 Free RAM: 1,098,649K (  421,677K cached pss +   329,180K cached kernel +   347,792K free)
      ION:    57,896K (   57,932K mapped +       -36K unmapped +         0K pools)
      GPU:    53,544K (   52,276K dmabuf +     1,268K private)
 Used RAM: 1,019,667K (  748,431K used pss +   271,236K kernel)
 Lost RAM:   111,523K
     ZRAM:    70,036K physical used for   271,616K in swap (1,018,488K total swap)
   Tuning: 256 (large 384), oom   184,320K, restore limit    61,440K (high-end-gfx)
    """


# Main function call - commented out to prevent execution during code review
main()
