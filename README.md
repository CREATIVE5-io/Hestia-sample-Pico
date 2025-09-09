# Pico NTN Modbus Master

A comprehensive MicroPython implementation for Raspberry Pi Pico that provides NTN (Narrowband IoT) dongle communication functionality using Modbus RTU protocol. This library enables seamless integration with NTN dongles for IoT applications, including data transmission, device management, and LoRa network configuration.

## Features

### Core Functionality
- **Modbus RTU Master**: Full implementation of Modbus RTU protocol for industrial communication
- **NTN Dongle Support**: Complete integration with NTN dongles for cellular IoT connectivity
- **Thread-safe Operations**: Built-in locking mechanism for concurrent access
- **RS485 Interface**: Optimized for Pico-2CH-RS485 expansion board

### NTN Operations
- Device authentication and password management
- Real-time device status monitoring
- Network information retrieval (IMSI, SINR, RSRP)
- GPS location data access
- Uplink/downlink data transmission with JSON support
- Background downlink monitoring with threading

### LoRa Integration
- LoRa module configuration and parameter management
- Device private key management
- Public key configuration
- LoRa data retrieval and processing
- Channel plan and frequency management

## Hardware Requirements

- **Raspberry Pi Pico** or **Pico W**
- **Pico-2CH-RS485** expansion board
- **NTN Dongle** connected via RS485 interface
- **Power Supply**: Appropriate power source for Pico and peripherals

## Pin Configuration

### Default Configuration (UART1)
```python
UART_ID = 1
TX_PIN = 4    # GP4
RX_PIN = 5    # GP5
BAUDRATE = 115200
CTRL_PIN = None  # Set if DE/RE control is needed
```

### Alternative Configuration (UART0)
```python
UART_ID = 0
TX_PIN = 0    # GP0
RX_PIN = 1    # GP1
```

## Installation

1. **Copy the file** to your Raspberry Pi Pico:
   ```bash
   # Using Thonny IDE or similar
   cp pico_ntn_modbus_master.py /media/RPI-RP2/
   ```

2. **Required Dependencies**:
   - `umodbus` library (install via `upip install umodbus` if not included)
   - Standard MicroPython libraries: `machine`, `time`, `struct`, `json`, `re`, `binascii`, `sys`, `_thread`

## Quick Start

### Basic NTN Dongle Setup

```python
from pico_ntn_modbus_master import ntn_operation

# Initialize NTN dongle
ntn = ntn_operation(
    slave_address=1,
    uart_id=1,
    tx_pin=4,
    rx_pin=5,
    baudrate=115200
)

# Setup device password (required)
ntn.setup_device_password("00000000")

# Get device information
device_info = ntn.get_device_info()
print(f"Device Info: {device_info}")

# Get network status
status = ntn.get_device_status()
print(f"Device Status: {status}")
```

### Data Transmission

```python
# Send uplink data
sensor_data = {
    "temperature": 25.5,
    "humidity": 60.2,
    "timestamp": 1234567890
}

response = ntn.send_uplink_data(sensor_data)
if response:
    print(f"Server Response: {response}")
```

### Background Monitoring

```python
# Start downlink monitoring
ntn.start_downlink_monitor()

# Main application loop
while True:
    # Your application logic here
    time.sleep(60)

# Stop monitoring when done
ntn.stop_downlink_monitor()
```

## LoRa Configuration

### Basic LoRa Setup

```python
from pico_ntn_modbus_master import LoraConfig, setup_lora

# Initialize LoRa configuration
lora_conf = LoraConfig()

# Configure LoRa parameters
lora_conf.set_lora_params(
    frequency='923200000',  # 923.2 MHz
    sf='9',                 # Spreading Factor 9
    ch_plan='0'             # AS923 Channel Plan
)

# Add device private keys
lora_conf.add_device('device1', '0:002f2ebb:key1:key2')

# Setup LoRa module
setup_lora(ntn, lora_conf,
          setup_module=True,
          setup_privkeys=True)
```

### LoRa Data Retrieval

```python
# Get LoRa data from configured devices
lora_data = lora_get_data(ntn, lora_conf)
if lora_data:
    print(f"LoRa Data: {lora_data}")
```

## API Reference

### uModbusMaster Class

#### Constructor
```python
uModbusMaster(slave_address=1, uart_id=1, tx_pin=4, rx_pin=5,
              baudrate=115200, ctrl_pin=None, lock=None)
```

#### Key Methods
- `read_register(address, function_code=4)`: Read single register
- `read_registers(address, count, function_code=4)`: Read multiple registers
- `write_register(address, value)`: Write single register
- `write_registers(address, values)`: Write multiple registers
- `modbus_data_to_string(data)`: Convert Modbus data to string

### ntn_operation Class

#### Constructor
```python
ntn_operation(slave_address=1, uart_id=1, tx_pin=4, rx_pin=5,
              baudrate=115200, ctrl_pin=None, lock=None)
```

#### Device Management
- `setup_device_password(password="00000000")`: Set device access password
- `get_imsi()`: Retrieve IMSI
- `get_device_info()`: Get comprehensive device information
- `get_device_status()`: Check device readiness status
- `is_upload_avaliable()`: Check if upload buffer is available for data transmission

#### Network Operations
- `get_network_info()`: Get SINR, RSRP information
- `get_gps_info()`: Retrieve GPS coordinates
- `send_uplink_data(data_dict)`: Send JSON data to server
- `check_downlink_data()`: Check for incoming data

#### Monitoring
- `start_downlink_monitor()`: Start background downlink monitoring
- `stop_downlink_monitor()`: Stop monitoring thread
- `pause()` / `resume()`: Control monitoring state

### LoraConfig Class

#### Constructor
```python
LoraConfig()
```

#### Configuration Methods
- `set_lora_params(frequency, sf, ch_plan)`: Configure LoRa parameters
- `add_device(device_id, private_key)`: Add device private key
- `set_pubkey(pubkey)`: Set public key
- `get_lora_params()`: Retrieve current parameters

## Configuration Options

### Service Modes
- **Mode 1 (NIDD)**: Narrowband IoT Data Delivery
- **Mode 2 (UDP)**: UDP socket communication

### LoRa Channel Plans
- `0`: AS923 (Asia)
- `1`: US915 (North America)
- `2`: AU915 (Australia)
- `3`: EU868 (Europe)
- `4`: KR920 (South Korea)
- `5`: IN865 (India)
- `6`: RU864 (Russia)

## Usage Examples

### Complete IoT Application

```python
import time
from pico_ntn_modbus_master import ntn_operation, LoraConfig, setup_lora

def main():
    # Initialize NTN dongle
    ntn = ntn_operation(baudrate=115200)

    # Setup password
    ntn.setup_device_password()

    # Configure LoRa
    lora_conf = LoraConfig()
    lora_conf.set_lora_params(frequency='923200000', sf='9', ch_plan='0')
    setup_lora(ntn, lora_conf, setup_module=True)

    # Start monitoring
    ntn.start_downlink_monitor()

    try:
        while True:
            # Check device status
            status = ntn.get_device_status()
            if status and status['all_ready']:
                # Send sensor data
                data = {"sensor": "active", "value": 42}
                ntn.send_uplink_data(data)

            time.sleep(300)  # 5 minutes

    except KeyboardInterrupt:
        ntn.stop_downlink_monitor()
        print("Application stopped")

if __name__ == '__main__':
    main()
```

### LoRa Setup Only Mode

```python
# Run LoRa configuration only
from pico_ntn_modbus_master import demo_lora_setup

demo_lora_setup()
```

## Troubleshooting

### Common Issues

1. **Connection Failed**
   - Verify RS485 connections
   - Check baudrate settings
   - Ensure proper power supply

2. **Authentication Error**
   - Verify device password
   - Check NTN dongle compatibility

3. **No Data Transmission**
   - Confirm network registration
   - Check service mode configuration
   - Verify JSON data format

4. **LoRa Configuration Failed**
   - Ensure correct frequency for region
   - Verify channel plan settings
   - Check device key formats

### Debug Information

Enable debug output by monitoring serial console for detailed error messages and status information.

## Dependencies

- **umodbus**: Modbus RTU implementation for MicroPython
- **machine**: Hardware control (UART, Pin)
- **time**: Timing and delays
- **struct**: Binary data handling
- **json**: JSON data processing
- **re**: Regular expressions for parsing
- **binascii**: Binary data conversion
- **sys**: System operations
- **_thread**: Threading support

## License

This project is open-source. Please refer to the original source files for licensing information.

## Contributing

Contributions are welcome! Please ensure code follows MicroPython best practices and includes appropriate documentation.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the API documentation
3. Verify hardware connections
4. Ensure all dependencies are installed

## Version History

- **Current Version**: Based on ntn_modbus_master_sample.py and umodbus_rtu_master.py
- **MicroPython Compatibility**: Tested on Raspberry Pi Pico
- **Hardware**: Optimized for Pico-2CH-RS485 board

---

*This README provides comprehensive documentation for the Pico NTN Modbus Master implementation. For the latest updates and additional examples, please refer to the source code comments and documentation.*
