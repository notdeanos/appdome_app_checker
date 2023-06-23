#!/usr/bin/env python3


import subprocess
import json
import sys
import os


# Check if a binary is available in the system PATH
def is_binary_available(binary):
    try:
        subprocess.check_output(['which', binary])
        return True
    except subprocess.CalledProcessError:
        return False


# Install missing binaries/packages
def install_missing_binaries(missing_binaries):
    missing_packages = {
        'frida-ios-dump': 'frida-ios-dump',
        'jadx': 'jadx',
        'unzip': 'unzip',
        'plutil': 'plutil',
        'aapt': 'aapt',
        'strings': 'binutils'
    }

    for binary in missing_binaries:
        if binary in missing_packages:
            package_name = missing_packages[binary]
            print(f"Installing {package_name}...")
            subprocess.call(['sudo', 'apt', 'install', '-y', package_name])


# Check for obfuscation in the app
def check_for_obfuscation(file_path, file_extension):
    # Check if all required binaries are available
    required_binaries = ['frida-ios-dump', 'jadx', 'unzip', 'plutil', 'aapt', 'strings']
    missing_binaries = [binary for binary in required_binaries if not is_binary_available(binary)]

    if missing_binaries:
        print("The following required binaries are missing:")
        for binary in missing_binaries:
            print(f"- {binary}")
        install_prompt = input("Do you want to install the missing binaries/packages? (y/n): ")
        if install_prompt.lower() == 'y':
            install_missing_binaries(missing_binaries)
        else:
            print("Cannot proceed without the required binaries. Exiting...")
            return

    # Create a temporary directory for extraction
    temp_dir = 'temp'
    os.makedirs(temp_dir, exist_ok=True)

    # Extract the app files based on the file extension
    if file_extension == '.ipa':  # iOS app
        subprocess.call(['unzip', '-o', file_path, '-d', temp_dir])
        app_binary = subprocess.check_output(['find', temp_dir, '-name', '*.app']).decode().strip()
        check_ios_permissions(app_binary)
        check_debuggable_ios(app_binary)
        check_root_detection_ios(app_binary)
        check_frida_detection_ios(app_binary)
        check_ssl_pinning_ios(app_binary)
        check_anti_tampering_protection_ios(app_binary)
    elif file_extension == '.apk' or file_extension == '.aab':  # Android app or app bundle
        subprocess.call(['unzip', '-o', file_path, '-d', temp_dir])
        app_binary = os.path.join(temp_dir, 'base.apk')
        check_android_permissions(app_binary)
        check_debuggable_android(app_binary)
        check_root_detection_android(app_binary)
        check_frida_detection_android(app_binary)
        check_ssl_pinning_android(app_binary)
        check_anti_tampering_protection_android(app_binary)
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
    result = subprocess.check_output(['aapt', 'd', 'permissions', app_binary])
    result_str = result.decode()
    print("Permissions:")
    print(result_str)


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
    result = subprocess.check_output(['aapt', 'd', 'badging', app_binary])
    result_str = result.decode()
    if 'debuggable' in result_str:
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
    result = subprocess.check_output(['jadx', app_binary, '-j', 'AndroidManifest.xml'])
    result_str = result.decode().lower()
    if 'android:name=".frida.fridaapplication"' in result_str:
        print("The iOS app has anti-tampering protection.")


# Check for anti-tampering protection (Android)
def check_anti_tampering_protection_android(app_binary):
    result = subprocess.check_output(['jadx', app_binary, '-j', 'AndroidManifest.xml'])
    result_str = result.decode().lower()
    if 'android:name=".frida.fridaapplication"' in result_str:
        print("The Android app has anti-tampering protection.")


# Main function
def main():
    if len(sys.argv) < 2:
        print("Usage: python obfuscation_checker.py <file_path>")
        return

    file_path = sys.argv[1]
    _, file_extension = os.path.splitext(file_path)

    check_for_obfuscation(file_path, file_extension)


if __name__ == '__main__':
    main()
