from network_utils import discover_hosts
import inquirer

def print_network_info(interface, local_ip, gateway_ip):
    """
    Prints the local network informations with a border.
    """
    info_lines = [
        f"Network info:",
        f"Interface: {interface}",
        f"Local IP:  {local_ip}",
        f"Gateway:   {gateway_ip}"
    ]
    width = max(len(line) for line in info_lines)
    border = "+" + "-" * (width + 2) + "+"

    print(border)
    for line in info_lines:
        print(f"| {line.ljust(width)} |")
    print(border)

def select_target_device(local_ip):
    """
    Uses the discovered hosts from network_utils to let the user select a target device.
    Returns selected target(target_ip, target_mac, target_name).
    """
    devices = discover_hosts(local_ip)
    if not devices:
        print("❌ No devices found on the network.")
        return None, None, None

    choices = [
        (f"{device['name']} | IP: {device['ip']} | MAC: {device['mac']}", idx)
        for idx, device in enumerate(devices)
    ]

    questions = [
        inquirer.List(
            "device",
            message="Select a target device",
            choices=choices,
        )
    ]
    answer = inquirer.prompt(questions)
    if answer is None:
        return None, None, None

    selected = devices[answer["device"]]
    return selected['ip'], selected['mac'], selected['name']