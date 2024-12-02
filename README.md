# fakenmap
import socket
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

# Hàm quét cổng
def scan_port(ip, port):
    try:
        # Tạo socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Thời gian timeout
            result = s.connect_ex((ip, port))
            if result == 0:
                return f"Port {port} is OPEN"
            else:
                return None
    except Exception as e:
        return None

# Hàm quét toàn bộ dải cổng
def scan_ports(ip, port_range=(1, 1024)):
    print(f"Scanning {ip} for ports {port_range[0]}-{port_range[1]}...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(port_range[0], port_range[1] + 1)]
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

# Kiểm tra lỗ hổng cơ bản với một số cổng tiêu chuẩn
def vulnerability_check(ip, open_ports):
    vuln_info = {
        21: "FTP Service - Check for anonymous access vulnerability",
        22: "SSH Service - Weak password vulnerability",
        80: "HTTP Service - Check for outdated server versions",
        443: "HTTPS Service - Check for SSL/TLS issues",
    }
    print("\nPotential vulnerabilities:")
    for port_info in open_ports:
        port = int(port_info.split()[1])
        if port in vuln_info:
            print(f"{port_info}: {vuln_info[port]}")
        else:
            print(f"{port_info}: No known vulnerabilities detected.")

# Nhập địa chỉ IP và dải cổng
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    port_range = (1, 1024)  # Quét các cổng từ 1 đến 1024 (có thể điều chỉnh)
    
    open_ports = scan_ports(target_ip, port_range)
    if open_ports:
        print("\nOpen ports:")
        for port in open_ports:
            print(port)
        vulnerability_check(target_ip, open_ports)
    else:
        print("\nNo open ports detected.")
