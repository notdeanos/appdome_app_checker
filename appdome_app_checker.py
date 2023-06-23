#!/usr/bin/env python3

"""
Appdome App Checker

Dean Mcdonald <dean@appdome.com> (c) Appdome, 2023.

This script analyzes mobile app files (IPA and APK) to detect various security-related properties and anti-tampering measures.
It performs static analysis on the provided app file to identify potential security risks and protections implemented.

The script supports both iOS (IPA) and Android (APK) app files and checks for the following:

- App permissions (both iOS and Android)
- Debuggable flag (both iOS and Android)
- Root detection (both iOS and Android)
- Frida detection (both iOS and Android)
- SSL/TLS pinning (both iOS and Android)
- Anti-tampering protection (both iOS and Android)
- Magisk detection (Android only)
- Zygisk detection (Android only)

Usage: python appdome_app_checker.py [APP_FILE]

[APP_FILE] - Path to the app file (IPA or APK) to be analyzed.

Note: Ensure that the required dependencies (frida-ios-dump, jadx, unzip, plutil, aapt, strings) are installed.

"""
import subprocess
import json
import sys
import os
from androguard.core.bytecodes.apk import APK
from subprocess import DEVNULL

# Check if a binary is available in the system PATH
def is_binary_available(binary):
    try:
        subprocess.check_output(['which', binary])
        return True
    except subprocess.CalledProcessError:
        return False


# Install missing binaries/packages using brew
def install_missing_binaries(missing_binaries):
    for binary in missing_binaries:
        if not is_binary_available(binary):
            print(f"Installing {binary}...")
            subprocess.call(['brew', 'install', binary])


# Check for obfuscation and perform necessary checks based on the file extension
def check_for_obfuscation(file_path, file_extension):
    # Check if all required binaries are available
    required_binaries = ['frida-ios-dump', 'jadx', 'unzip', 'plutil', 'strings']
    for binary in required_binaries:
        if not is_binary_available(binary):
            print(f"Error: {binary} not found. Make sure it is installed and accessible in the system PATH.")
            return

    # Create a temporary directory for extraction
    temp_dir = 'temp'
    os.makedirs(temp_dir, exist_ok=True)

    # Extract the app files based on the file extension
    if file_extension == '.ipa':  # iOS app
        subprocess.call(['unzip', '-qq', '-o', file_path, '-d', temp_dir], stdout=DEVNULL, stderr=DEVNULL)
        app_binary = subprocess.check_output(['find', temp_dir, '-name', '*.app']).decode().strip()
        check_ios_permissions(app_binary)
        check_debuggable_ios(app_binary)
        check_root_detection_ios(app_binary)
        check_frida_detection_ios(app_binary)
        check_ssl_pinning_ios(app_binary)
        check_anti_tampering_protection_ios(app_binary)
    elif file_extension == '.apk' or file_extension == '.aab':  # Android app or app bundle
        subprocess.call(['unzip', '-o', file_path, '-d', temp_dir])
        apk_files = [f for f in os.listdir(temp_dir) if f.endswith('.apk')]
        if apk_files:
            app_binary = os.path.abspath(os.path.join(temp_dir, apk_files[0]))
        else:
            print("No APK file found in the extracted directory.")
            return
        check_android_permissions(app_binary)
        check_debuggable_android(app_binary)
        check_root_detection_android(app_binary)
        check_frida_detection_android(app_binary)
        check_ssl_pinning_android(app_binary)
        check_anti_tampering_protection_android(app_binary)
        check_magisk_detection(app_binary)
        check_zygisk_detection_android(app_binary)
    else:
        print("Unsupported file format.")
        return

    # Cleanup temporary files
    subprocess.call(['rm', '-rf', temp_dir])

# Check app permissions (iOS)
def check_ios_permissions(app_binary):
    plist_path = os.path.join(app_binary, 'Info.plist')
    if os.path.exists(plist_path):
        try:
            result = subprocess.check_output(['plutil', '-p', plist_path])
            plist_data = json.loads(result)
            if 'CFBundleShortVersionString' in plist_data:
                app_version = plist_data['CFBundleShortVersionString']
                print("App Version:", app_version)
            if 'CFBundleIdentifier' in plist_data:
                bundle_id = plist_data['CFBundleIdentifier']
                print("Bundle Identifier:", bundle_id)
            if 'UIRequiredDeviceCapabilities' in plist_data:
                required_capabilities = plist_data['UIRequiredDeviceCapabilities']
                print("Required Device Capabilities:")
                for capability in required_capabilities:
                    print("-", capability)
            if 'NSCameraUsageDescription' in plist_data:
                camera_usage_desc = plist_data['NSCameraUsageDescription']
                print("Camera Usage Description:", camera_usage_desc)
            if 'NSMicrophoneUsageDescription' in plist_data:
                microphone_usage_desc = plist_data['NSMicrophoneUsageDescription']
                print("Microphone Usage Description:", microphone_usage_desc)
        except:
            pass


# Check app permissions (Android)
def check_android_permissions(app_binary):
    with APK(app_binary) as apk:
        manifest_data = apk.get_manifest_xml()
    permissions = apk.get_permissions()
    if permissions:
        print("Permissions:")
        for permission in permissions:
            print("-", permission)


# Check if the app is debuggable (iOS)
def check_debuggable_ios(app_binary):
    plist_path = os.path.join(app_binary, 'Info.plist')
    if os.path.exists(plist_path):
        try:
            result = subprocess.check_output(['plutil', '-p', plist_path])
            plist_data = json.loads(result)
            if 'Entitlements' in plist_data:
                entitlements = plist_data['Entitlements']
                if 'get-task-allow' in entitlements and entitlements['get-task-allow']:
                    print("The iOS app is debuggable.")
        except:
            pass


# Check if the app is debuggable (Android)
def check_debuggable_android(app_binary):
    apk = APK(app_binary)
    with APK(app_binary) as apk:
        manifest_data = apk.get_manifest_xml()
    debuggable = apk.get_effective_debug()
    if debuggable:
        print("The Android app is debuggable.")


# Check for root detection (iOS)
def check_root_detection_ios(app_binary):
    result = subprocess.check_output(['strings', app_binary])
    result_str = result.decode().lower()
    if 'cydia' in result_str or 'jailbreak' in result_str:
        print("The iOS app has signs of root detection.")


# Check for root detection (Android)
def check_root_detection_android(app_binary):
    result = subprocess.check_output(['strings', app_binary])
    result_str = result.decode().lower()
    if 'root' in result_str or 'su' in result_str:
        print("The Android app has signs of root detection.")


# Check for Frida detection (iOS)
def check_frida_detection_ios(app_binary):
    result = subprocess.check_output(['strings', app_binary])
    result_str = result.decode().lower()
    if 'frida' in result_str:
        print("The iOS app has signs of Frida detection.")


# Check for Frida detection (Android)
def check_frida_detection_android(app_binary):
    result = subprocess.check_output(['strings', app_binary])
    result_str = result.decode().lower()
    if 'frida' in result_str:
        print("The Android app has signs of Frida detection.")


# Check for SSL/TLS pinning (iOS)
def check_ssl_pinning_ios(app_binary):
    result = subprocess.check_output(['strings', app_binary])
    result_str = result.decode().lower()
    if 'sslpinning' in result_str or 'ssl pinning' in result_str:
        print("The iOS app has signs of SSL/TLS pinning.")


# Check for SSL/TLS pinning (Android)
def check_ssl_pinning_android(app_binary):
    result = subprocess.check_output(['strings', app_binary])
    result_str = result.decode().lower()
    if 'sslpinning' in result_str or 'ssl pinning' in result_str:
        print("The Android app has signs of SSL/TLS pinning.")


# Check for anti-tampering protection (iOS)
def check_anti_tampering_protection_ios(app_binary):
    result = subprocess.check_output(['jadx', '-j', app_binary])
    result_str = result.decode().lower()
    if 'j2waf' in result_str or 'tamper' in result_str:
        print("The iOS app has signs of anti-tampering protection.")


# Check for anti-tampering protection (Android)
def check_anti_tampering_protection_android(app_binary):
    result = subprocess.check_output(['jadx', '-j', app_binary])
    result_str = result.decode().lower()
    if 'j2waf' in result_str or 'tamper' in result_str:
        print("The Android app has signs of anti-tampering protection.")


# Check for Magisk detection (Android)
def check_magisk_detection(app_binary):
    with APK(app_binary) as apk:
        manifest_data = apk.get_manifest_xml()
    magisk_detection = 'com.topjohnwu.magisk' in manifest_data
    if magisk_detection:
        print("Magisk Detection: Detected")
    else:
        print("Magisk Detection: Not Detected")


# Check for Zygisk detection (Android)
def check_zygisk_detection_android(app_binary):
    result = subprocess.check_output(['strings', app_binary])
    result_str = result.decode().lower()
    if 'zygisk' in result_str:
        print("The Android app has signs of Zygisk detection.")



# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python appdome_app_checker.py [APP_FILE]")
        return

    app_file = sys.argv[1]
    file_name, file_extension = os.path.splitext(app_file)
    file_extension = file_extension.lower()

    if not os.path.isfile(app_file):
        print("Error: File not found.")
        return

    check_for_obfuscation(app_file, file_extension)


if __name__ == "__main__":
    main()



