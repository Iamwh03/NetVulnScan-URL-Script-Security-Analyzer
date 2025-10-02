# agent.py
# A real-time command monitoring agent for Windows using the standard pywin32 library.
# IMPORTANT: This script must be run with Administrator privileges.

import time
import xml.etree.ElementTree as ET
import win32evtlog
import win32event
from backend import HybridDetectionEngine


def get_command_line_from_event(event):
    """Parses the XML of an event to find the command line."""
    try:
        xml_data = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
        root = ET.fromstring(xml_data)

        # Define the XML namespace to find elements correctly
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        # Find the 'CommandLine' element (EventData -> Data)
        command_line_element = root.find(".//e:Data[@Name='CommandLine']", ns)

        if command_line_element is not None and command_line_element.text:
            return command_line_element.text
    except Exception:
        # Some events might not have the expected XML structure
        pass
    return None


def main():
    print("[+] Real-Time Monitoring Agent Started...")
    print("[+] This script requires Administrator rights to access the Security Log.")
    print("[+] Waiting for new command events... (Press Ctrl+C to stop)")

    try:
        engine = HybridDetectionEngine()

        # Open the "Security" event log
        log_handle = win32evtlog.OpenEventLog(None, "Security")

        # Create an event object that Windows will signal when a new log entry is written
        event_handle = win32event.CreateEvent(None, 0, 0, None)

        # Tell Windows to signal our event object when the Security log changes
        win32evtlog.NotifyChangeEventLog(log_handle, event_handle)

    except Exception as e:
        print(f"\n[!!!] FATAL ERROR: Could not set up the event log monitor.")
        print(f"[!!!] Please make sure you are running this script as an Administrator.")
        print(f"[!!!] Error details: {e}")
        return

    # Get the total number of records to start reading from the end
    total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)
    current_record = total_records

    try:
        while True:
            # Wait for Windows to signal a new event (with a 1-second timeout)
            wait_result = win32event.WaitForSingleObject(event_handle, 1000)

            # If the signal was received
            if wait_result == win32event.WAIT_OBJECT_0:
                new_total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)

                # Read all new records since the last check
                if new_total_records > current_record:
                    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
                    events = win32evtlog.ReadEventLog(log_handle, flags, current_record)

                    for event in events:
                        if event.EventID == 4688:  # Event ID for "A new process has been created"
                            command_line = get_command_line_from_event(event.GetHandle())
                            if command_line:
                                print("\n" + "=" * 60)
                                print(f"[*] Detected Command: {command_line}")

                                # Analyze the command
                                findings = engine.analyze(command_line)
                                score = sum(engine.score_weights.get(cat, 0) for cat in findings if
                                            cat not in ['whitelisted', 'machine_learning'])

                                if score > 0:
                                    print(f"  [!] Rule-Based Risk Score: {score * 100:.1f}%")
                                    print(f"  [!] Matched Categories: {list(findings.keys())}")

                current_record = new_total_records

    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped by user.")
    finally:
        win32evtlog.CloseEventLog(log_handle)


if __name__ == "__main__":
    main()