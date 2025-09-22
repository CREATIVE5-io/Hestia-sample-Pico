"""
MicroPython Modbus RTU Master for Raspberry Pi Pico with Pico-2CH-RS485
Based on ntn_modbus_master_sample.py and umodbus_rtu_master.py

This code provides NTN dongle communication functionality for MicroPython
on Raspberry Pi Pico with RS485 interface.

Hardware Requirements:
- Raspberry Pi Pico or Pico W
- Pico-2CH-RS485 expansion board
- NTN dongle connected via RS485

Pin Configuration for Pico-2CH-RS485:
- UART1: GP4 (TX), GP5 (RX) - Channel 1
- UART0: GP0 (TX), GP1 (RX) - Channel 2 (alternative)
- DE/RE control pins may vary based on board design
"""

import struct
import json
import time
import _thread
import re
import binascii
import sys
from time import sleep
from machine import Pin, UART
from umodbus.serial import Serial as ModbusRTUMaster

# Global thread control variables
_thread_running = False
_shutdown_flag = False

class uModbusMaster:
    """
    Modbus Master class for Raspberry Pi Pico with RS485 interface
    """
    
    def __init__(self, slave_address=1, uart_id=1, tx_pin=4, rx_pin=5, 
                 baudrate=115200, ctrl_pin=None, lock=None):
        """
        Initialize the Modbus RTU Master
        
        Args:
            slave_address (int): Modbus slave address (default: 1)
            uart_id (int): UART interface ID (0 or 1, default: 1)
            tx_pin (int): TX pin number (default: 4 for UART1)
            rx_pin (int): RX pin number (default: 5 for UART1)
            baudrate (int): Communication baudrate (default: 115200)
            ctrl_pin (int): DE/RE control pin for RS485 (optional)
        """
        self.slave_addr = slave_address
        if lock is None:
            self.lock = _thread.allocate_lock()  # Create a lock if none provided
        else:
            self.lock = lock  # lock for thread synchronization
        
        # Configure pins
        rtu_pins = (Pin(tx_pin), Pin(rx_pin))
        
        try:
            # Initialize Modbus RTU Master
            self.master = ModbusRTUMaster(
                pins=rtu_pins,
                baudrate=baudrate,
                data_bits=8,
                stop_bits=1,
                parity=None,
                ctrl_pin=ctrl_pin,
                uart_id=uart_id
            )
            print(f'NTN Modbus Master initialized on UART{uart_id}')
            print(f'TX: GP{tx_pin}, RX: GP{rx_pin}, Baudrate: {baudrate}')
            
        except Exception as e:
            print(f'Failed to initialize Modbus Master: {e}')
            raise
    
    def read_register(self, register_address, function_code=4):
        """
        Read a single input/holding register
        
        Args:
            register_address (int): Register address to read
            function_code (int): Modbus function code (3 for holding, 4 for input)
            
        Returns:
            int: Register value or None if error
        """
        with self.lock:
            try:
                if function_code == 3:
                    result = self.master.read_holding_registers(
                        self.slave_addr, register_address, 1, False
                    )
                elif function_code == 4:
                    result = self.master.read_input_registers(
                        self.slave_addr, register_address, 1, False
                    )
                else:
                    print(f"Invalid function code: {function_code}")
                    return None
                return result[0] if result else None
            except Exception as e:
                print(f"Error reading register {hex(register_address)}: {e}")
                return None
    
    def read_registers(self, register_address, count, function_code=4):
        """
        Read multiple input registers
        
        Args:
            register_address (int): Starting register address
            count (int): Number of registers to read
            function_code (int): Modbus function code (3 for holding, 4 for input)
            
        Returns:
            list: List of register values or None if error
        """
        with self.lock:
            try:
                if function_code == 3:
                    result = self.master.read_holding_registers(
                        self.slave_addr, register_address, count, False
                    )
                elif function_code == 4:
                    result = self.master.read_input_registers(
                        self.slave_addr, register_address, count, False
                    )
                else:
                    print(f"Invalid function code: {function_code}")
                    return None
                if result and all(x == 0 for x in result):
                    return None
                return result
            except Exception as e:
                print(f"Error reading registers {hex(register_address)}: {e}")
                return None
   
    def write_register(self, register_address, value):
        """
        Write a single holding register
        
        Args:
            register_address (int): Register address to write
            value (int): Value to write
            
        Returns:
            bool: True if successful, False otherwise
        """
        with self.lock:
            try:
                result = self.master.write_single_register(
                    self.slave_addr, register_address, value, False
                )
                return result is not None
            except Exception as e:
                print(f"Error writing register {hex(register_address)}: {e}")
                return False
    
    def write_registers(self, register_address, values):
        """
        Write multiple holding registers
        
        Args:
            register_address (int): Starting register address
            values (list): List of values to write
            
        Returns:
            bool: True if successful, False otherwise
        """
        with self.lock:
            try:
                if values is not None:
                    result = self.master.write_multiple_registers(
                        self.slave_addr, register_address, values, False
                    )
                    return result is not None
                return False
            except Exception as e:
                print(f"Error writing registers {hex(register_address)}: {e}")
                return False
    
    @staticmethod
    def modbus_data_to_string(modbus_data):
        """
        Convert Modbus register data to string
        
        Args:
            modbus_data (list): List of 16-bit register values
            
        Returns:
            str: Decoded string or None if error
        """
        try:
            byte_data = b''.join(struct.pack('>H', value) for value in modbus_data)
            return byte_data.decode('utf-8').rstrip('\x00')
        except Exception as e:
            print(f"Error decoding Modbus data: {e}")
            return None
        
    @staticmethod
    def bytes_to_integers(byte_list):
        print(f'Byte list: {byte_list}')
        return [int.from_bytes(b, 'big') for b in byte_list]

    @staticmethod
    def bytes_to_list_with_padding(data):
        chunks = [data[i:i+2] for i in range(0, len(data), 2)]
        if len(chunks[-1]) < 2:
            chunks[-1] = chunks[-1].ljust(2, b'0')
        print(f'Chunks: {chunks}')
        return uModbusMaster.bytes_to_integers(chunks)
    
class ntn_operation(uModbusMaster):
    def __init__(self, slave_address=1, uart_id=1, tx_pin=4, rx_pin=5,
                    baudrate=115200, ctrl_pin=None, lock=None):
        super().__init__(slave_address, uart_id, tx_pin, rx_pin, baudrate, ctrl_pin, lock)
        self.passwd_set = False
        self.srv_mode = 1  # 'NIDD' or 'UDP'
        self.thread_running = False
        self.pause_flag = True
        
    def setup_device_password(self, password="00000000"):
        """
        Setup device password (required for NTN dongle access)
        
        Args:
            password (str): 8-character hex password (default: "00000000")
            
        Returns:
            bool: True if successful
        """
        try:
            # Convert password string to list of integers
            passwd_list = [int(password[i:i+2], 16) for i in range(0, len(password), 2)]
            print(f'Setting password: {passwd_list}')
            
            result = self.write_registers(0x0000, passwd_list)
            if result:
                self.passwd_set = True
                self.get_service_mode()
                print('Password set successfully')
                return True
            else:
                print('Password set failed')
                return False
        except Exception as e:
            print(f'Error setting password: {e}')
            return False
   
    def get_imsi(self):
        """
        Read IMSI from the device
        
        Returns:
            str: IMSI string or None if error
        """
        imsi_data = self.read_registers(0xEB00, 8)
        if imsi_data:
            imsi = self.modbus_data_to_string(imsi_data)
            print(f'IMSI: {imsi}')
            return imsi
        else:
            print('Failed to read IMSI')
            return None
        
    def get_device_info(self):
        """
        Read and display basic device information
        
        Returns:
            dict: Device information dictionary
        """
        info = {}
        
        # Read Serial Number
        sn_data = self.read_registers(0xEA60, 6)
        if sn_data:
            sn = self.modbus_data_to_string(sn_data)
            info['serial_number'] = sn
            print(f'Serial Number: {sn}')
        
        # Read Model Name
        model_data = self.read_registers(0xEA66, 5)
        if model_data:
            model = self.modbus_data_to_string(model_data)
            info['model'] = model
            print(f'Model: {model}')
        
        # Read Firmware Version
        fw_data = self.read_registers(0xEA6B, 2)
        if fw_data:
            fw_ver = self.modbus_data_to_string(fw_data)
            info['firmware'] = fw_ver
            print(f'Firmware: {fw_ver}')
        
        # Read Hardware Version
        hw_data = self.read_registers(0xEA6D, 2)
        if hw_data:
            hw_ver = self.modbus_data_to_string(hw_data)
            info['hardware'] = hw_ver
            print(f'Hardware: {hw_ver}')
        
        # Read Modbus ID
        modbus_id = self.read_register(0xEA6F)
        if modbus_id:
            info['modbus_id'] = modbus_id
            print(f'Modbus ID: {modbus_id}')
        
        # Read Heartbeat
        heartbeat = self.read_register(0xEA70)
        if heartbeat:
            info['heartbeat'] = heartbeat
            print(f'Heartbeat: {heartbeat}')
        
        return info
    
    def get_network_info(self):
        """
        Read network-related information
        
        Returns:
            dict: Network information dictionary
        """
        info = {}
        
        # Read SINR
        sinr_data = self.read_registers(0xEB13, 2)
        if sinr_data:
            sinr = self.modbus_data_to_string(sinr_data)
            info['sinr'] = sinr
            print(f'SINR: {sinr}')
        
        # Read RSRP
        rsrp_data = self.read_registers(0xEB15, 2)
        if rsrp_data:
            rsrp = self.modbus_data_to_string(rsrp_data)
            info['rsrp'] = rsrp
            print(f'RSRP: {rsrp}')
        
        return info
    
    def get_gps_info(self):
        """
        Read GPS-related information

        Returns:
            dict: GPS information dictionary
        """
        info = {}
        # Read Latitude
        lat_data = self.read_registers(0xEB1B, 5)
        if lat_data:
            latitude = self.modbus_data_to_string(lat_data)
            info['latitude'] = float(latitude)
            print(f'Latitude: {latitude}')
        
        # Read Longitude
        lon_data = self.read_registers(0xEB20, 6)
        if lon_data:
            longitude = self.modbus_data_to_string(lon_data)
            info['longitude'] = float(longitude)
            print(f'Longitude: {longitude}')
        
        return info
   
    def get_device_status(self):
        """
        Read and interpret device status
        
        Returns:
            dict: Status information
        """
        status_reg = self.read_register(0xEA71)
        if not status_reg:
            return None
        
        status = {}
       
        if self.srv_mode == 1: 
            status['module_at_ready'] = bool(status_reg & 0x01)
            status['downlink_ready'] = bool((status_reg & 0x02) >> 1)
            status['sim_ready'] = bool((status_reg & 0x04) >> 2)
            status['network_registered'] = bool((status_reg & 0x08) >> 3)
            status['all_ready'] = ((status_reg & 0x0F)== 0x0F)
        elif self.srv_mode == 2:
            status['module_at_ready'] = bool(status_reg & 0x01)
            status['ip_ready'] = bool((status_reg & 0x02) >> 1)
            status['sim_ready'] = bool((status_reg & 0x04) >> 2)
            status['network_registered'] = bool((status_reg & 0x08) >> 3)
            status['socket_ready'] = bool((status_reg & 0x10) >> 4)
            status['all_ready'] = ((status_reg & 0x1F) == 0x1F)
 
        status['raw_status'] = tuple((status_reg >> (7-i)) & 1 for i in range(8))
        return status
   
    def get_service_mode(self):
        srv_mode = self.read_register(0xEB29)
        if srv_mode != None:
            print(f'Service mode: {srv_mode} (1:NIDD, 2:UDP)')
            self.srv_mode = srv_mode
        return srv_mode

    def is_upload_avaliable(self):
        """
        Check if upload buffer is available
        
        Returns:
            bool: True if upload buffer is available
        """
        upload_avbl = self.read_register(0xEA7D)
        if upload_avbl != None and upload_avbl == 0:
            return True
        return False
        
    def send_uplink_data(self, data_dict):
        """
        Send uplink data to the network
        
        Args:
            data_dict (dict): Data to send (will be JSON encoded)
            
        Returns:
            str: Response data or None if error
        """
        try:
            # Convert data to JSON and then to bytes
            json_str = json.dumps(data_dict)
            json_bytes = json_str.encode()
            hex_data = json_bytes.hex().encode('ascii')
            
            # Convert to Modbus format
            modbus_data = uModbusMaster.bytes_to_list_with_padding(hex_data)
            modbus_data.append(3338)

            # Send data
            result = self.write_registers(0xC550, modbus_data)
            if not result:
                print('Failed to send uplink data')
                return None
            
            # Wait for response
            timeout = 30  # 30 seconds timeout
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                data_len = self.read_register(0xF060)
                if data_len and data_len > 0:
                    print(f'Response data length: {data_len}')
                    response_data = self.read_registers(0xF061, data_len)
                    if response_data:
                        response_str = self.modbus_data_to_string(response_data)
                        return response_str
                    break
                time.sleep(1)
            
            print('No response received within timeout')
            return None
            
        except Exception as e:
            print(f'Error sending uplink data: {e}')
            return None
    
    def check_downlink_data(self):
        """
        Check for incoming downlink data
        
        Returns:
            dict: Downlink data or None if no data
        """
        try:
            data_len = self.read_register(0xEC60)
            if data_len and data_len > 0:
                print(f'Downlink data length: {data_len}')
                
                dl_data = self.read_registers(0xEC61, data_len)
                if dl_data:
                    # Convert to bytes and decode
                    byte_data = b''.join(struct.pack('>H', v) for v in dl_data)
                    downlink_data = json.loads(binascii.unhexlify(byte_data).decode('utf-8'))
                    
                    print(f'Downlink data: {downlink_data}')
                    return downlink_data
            
            return None
            
        except Exception as e:
            print(f'Error checking downlink data: {e}')
            return None
       
    def pause(self):
        """
        Pause the downlink monitoring thread
        """
        self.pause_flag = True
        print('Downlink monitoring paused')
        
    def resume(self):
        """
        Resume the downlink monitoring thread
        """
        self.pause_flag = False
        print('Downlink monitoring resumed')
         
    def downlink_monitor_thread(self):
        """
        Background thread to monitor downlink data
        
        Args:
            ntn_master: NTN Modbus Master instance
        """
        self.thread_running = True
        self.pause_flag = False
        print('Downlink monitor thread started')
        
        try:
            while self.thread_running:
                if self.pause_flag:
                    print('Downlink monitor paused')
                    time.sleep(1)
                    continue
                try:
                    downlink_data = self.check_downlink_data()
                    if downlink_data:
                        print(f'Received downlink: {downlink_data}')
                    else:
                        print('No downlink data')
                    time.sleep(1)
                except Exception as e:
                    print(f'Error in downlink monitor: {e}')
                    time.sleep(1)
        except Exception as e:
            print(f'Fatal error in downlink thread: {e}')
        finally:
            self.pause_flag = True
            self.thread_running = False
        print('Downlink monitor thread stopped')
        return 

    def start_downlink_monitor(self):
        """
        Start downlink monitoring thread with proper error handling
        
        Args:
            ntn_master: NTN Modbus Master instance
            
        Returns:
            bool: True if thread started successfully
        """
        
        try:
            _thread.start_new_thread(self.downlink_monitor_thread, ())
            # Wait a moment to ensure thread started
            time.sleep(0.1)
                    
            if self.thread_running:
                print('Downlink monitor started successfully')
                return True
            else:
                print('Failed to start downlink monitor')
                return False
        except Exception as e:
            print(f'Error starting downlink monitor: {e}')
            return False
        
    def stop_downlink_monitor(self):
        """
        Stop the downlink monitor thread
        """
        self.thread_running = False
        print('Stopping downlink monitor thread...')
        time.sleep(2)
        print('Downlink monitor thread has been stopped.')
    
    def _at_command_to_ascii(self, cmd):
        """
        Convert AT command string to list of ASCII codes
        
        Args:
            cmd (str): AT command string
            
        Returns:
            list: List of ASCII codes with padding
        """
        ascii_codes = []
        result = []
        for char in cmd:
            ascii_codes.append(ord(char))
        if len(ascii_codes) % 2 != 0:
            ascii_codes.append(0)

        # Process pairs of bytes
        for i in range(0, len(ascii_codes)-1, 2):
            # Shift first byte left 8 bits and add second byte
            combined = (ascii_codes[i] << 8) + ascii_codes[i + 1]
            result.append(combined)
        return result

    def pcie2_set_cmd(self, cmd):
        """
        Set command to PCIe2 module
        
        Args:
            cmd (str): AT command string
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if cmd is not None:
                # Convert AT command to ASCII codes
                cmd = cmd + '\r\n'
                ascii_cmd = self._at_command_to_ascii(cmd)
                print(f'ASCII command: {ascii_cmd}')
                result = self.write_registers(0xC700, ascii_cmd)
                return result
            else:
                return False
        except Exception as e:
            print(f'Error setting PCIe2 command: {e}')
            return False

    def pcie2_cmd(self, cmd):
        """
        Send command to PCIe2 module and get response
        
        Args:
            cmd (str): AT command string
            
        Returns:
            str: Response data or None if error
        """
        data = None
        if cmd == 'AT+BISGET=?':
            reg_data_len = 0xF460
            reg_data_start = 0xF461
        else:
            reg_data_len = 0xF860
            reg_data_start = 0xF861

        if cmd == 'ATZ':
            time_to_wait = 5
        else:
            time_to_wait = 3

        # Send command to PCIe2 module
        ret = self.pcie2_set_cmd(cmd)
        print(f'Command: {cmd}, ret: {ret}')
        if ret:
            time.sleep(time_to_wait)
            data_len_to_read = 0
            try:
                # Read response from PCIe2 module
                data_len_to_read = self.read_register(reg_data_len)
                print(f'data length to read: {hex(reg_data_len)}, {data_len_to_read}')
                if data_len_to_read:
                    print(f'data length to read: {data_len_to_read}')
                    a_codes = []
                    pcie2_data = self.read_registers(reg_data_start, data_len_to_read)
                    if pcie2_data:
                        for d in pcie2_data:
                            a_codes.append(d >> 8)
                            a_codes.append(d & 0xFF)
                        if cmd == 'AT+BISGET=?':
                            try:
                                idx_1st = a_codes.index(34)  # ASCII for '"'
                                print(f'Index: {idx_1st}')
                                idx_2nd = a_codes.index(34, idx_1st+1)
                                print(f'Index: {idx_2nd}')
                                a_codes = a_codes[idx_1st+1:idx_2nd]
                                print(f'a_codes: {a_codes}')
                                data = binascii.unhexlify(bytes(a_codes)).decode()
                            except (ValueError, UnicodeDecodeError) as e:
                                print(f'Error parsing BISGET response: {e}')
                                data = bytes(a_codes).decode()
                        else:
                            print(f'a_codes: {a_codes}')
                            data = bytes(a_codes).decode()
                    else:
                        data = None
            except Exception as e:
                print(f'Error reading PCIe2 response: {e}')
                return None
        return data

# === LoRa Configuration Handling ===
class LoraConfig:
    """
    LoRa configuration management for MicroPython
    Simplified version without file I/O dependencies
    """
    
    def __init__(self):
        """Initialize with default LoRa configuration"""
        # Default LoRa parameters
        self.lora_params = {
            'frequency': '923200000',
            'sf': '9',
            'ch_plan': '0'
        }
        
        # Default device private keys (empty by default)
        self.devices = {}
        
        # Default public key (empty by default)
        self.pubkey = None
        
        print('LoRa configuration initialized with defaults')
    
    def set_lora_params(self, frequency=None, sf=None, ch_plan=None):
        """
        Set LoRa parameters
        
        Args:
            frequency (str): LoRa frequency
            sf (str): Spreading factor
            ch_plan (str): Channel plan
        """
        if frequency:
            self.lora_params['frequency'] = frequency
        if sf:
            self.lora_params['sf'] = sf
        if ch_plan:
            self.lora_params['ch_plan'] = ch_plan
        print(f'LoRa params updated: {self.lora_params}')
    
    def get_lora_params(self):
        """Get LoRa parameters"""
        return self.lora_params
    
    def add_device(self, device_id, private_key):
        """
        Add device private key
        
        Args:
            device_id (str): Device identifier
            private_key (str): Private key string
        """
        self.devices[device_id] = private_key
        print(f'Added device {device_id}')
    
    def get_devices(self):
        """Get all devices"""
        return self.devices
    
    def set_pubkey(self, pubkey):
        """
        Set public key
        
        Args:
            pubkey (str): Public key string
        """
        self.pubkey = pubkey
        print(f'Public key set')
    
    def get_pubkey(self):
        """Get public key"""
        return self.pubkey

def setup_lora(ntn_dongle, lora_conf, setup_module=False, setup_privkeys=False, 
               cleanup_privkeys=False, setup_pubkey=False, cleanup_pubkey=False):
    """
    Setup LoRa module configuration
    
    Args:
        ntn_dongle: NTN Modbus Master instance
        lora_conf: LoraConfig instance
        setup_module (bool): Setup LoRa module parameters
        setup_privkeys (bool): Setup private keys
        cleanup_privkeys (bool): Cleanup private keys
        setup_pubkey (bool): Setup public key
        cleanup_pubkey (bool): Cleanup public key
    """
    print('--- LoRa Setup ---')
    data = ntn_dongle.pcie2_cmd('AT+BISFMT=1')
    print(f'response: {data}')
    
    params = lora_conf.get_lora_params()
    freq, sf, ch = params['frequency'], params['sf'], params['ch_plan']
    ch_plan_map = {"AS923": 0, "US915": 1, "AU915": 2, "EU868": 3, "KR920": 4, "IN865": 5, "RU864": 6}

    if setup_module:
        # Setup LoRa module
        data = ntn_dongle.pcie2_cmd('AT+BISRXF=?')
        if data:
            regex = re.compile(r'[:\s\n]+')
            freq_parts = regex.split(data)
            if len(freq_parts) > 2:
                freq_onDev = freq_parts[2]
                print(f'Current frequency: {freq_onDev}')
                if freq != freq_onDev:
                    data = ntn_dongle.pcie2_cmd('AT+BISRXF='+freq)
                    print(f'Set frequency response: {data}')
        
        data = ntn_dongle.pcie2_cmd('AT+BISRXSF=?')
        if data:
            regex = re.compile(r'[:\s\n]+')
            sf_parts = regex.split(data)
            if len(sf_parts) > 2:
                sf_onDev = sf_parts[2]
                print(f'Current SF: {sf_onDev}')
                if sf != sf_onDev:
                    data = ntn_dongle.pcie2_cmd('AT+BISRXSF='+sf)
                    print(f'Set SF response: {data}')
        
        data = ntn_dongle.pcie2_cmd('AT+BISCHPLAN=?')
        if data:
            regex = re.compile(r'[:\s\n]+')
            ch_parts = regex.split(data)
            if len(ch_parts) > 2:
                ch_onDev = ch_plan_map.get(ch_parts[2], 0)
                print(f'Current channel plan: {ch_onDev}')
                if int(ch) != ch_onDev:
                    data = ntn_dongle.pcie2_cmd('AT+BISCHPLAN='+ch)
                    print(f'Set channel plan response: {data}')

    if cleanup_privkeys:
        for i in range(16):
            cmd = f'AT+BISDEV={i}:ffffffff:ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff'
            data = ntn_dongle.pcie2_cmd(cmd)
            print(f'Cleanup device {i} response: {data}')

    if cleanup_pubkey:
        data = ntn_dongle.pcie2_cmd('AT+BISADMIN=ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff')
        print(f'Cleanup pubkey response: {data}')

    if setup_privkeys:
        devices = lora_conf.get_devices()
        print(f'LoRa devices: {devices}')
        for k, v in devices.items():
            print(f'Setting device {k}: {v}')
            data = ntn_dongle.pcie2_cmd('AT+BISDEV='+v)
            print(f'response: {data}')

    if setup_pubkey:
        pubkey = lora_conf.get_pubkey()
        if pubkey:
            data = ntn_dongle.pcie2_cmd('AT+BISADMIN='+pubkey)
            print(f'Set pubkey response: {data}')

    # Save and reset
    data = ntn_dongle.pcie2_cmd('AT+BISS')
    print(f'Save response: {data}')
    data = ntn_dongle.pcie2_cmd('ATZ')
    print(f'Reset response: {data}')

def lora_privkey_query(ntn_dongle, num_devices=16):
    """
    Query LoRa private keys
    
    Args:
        ntn_dongle: NTN Modbus Master instance
        num_devices (int): Number of devices to query
    """
    print('--- LoRa Private Key Query ---')
    for i in range(num_devices):
        cmd = f'AT+BISDEV={i}?'
        data = ntn_dongle.pcie2_cmd(cmd)
        if data:
            print(f'LoRa device {i}: {data}')
        else:
            print(f'LoRa device {i} query failed')

def lora_get_data(ntn_dongle, lora_conf):
    """
    Get LoRa data from devices
    
    Args:
        ntn_dongle: NTN Modbus Master instance
        lora_conf: LoraConfig instance
        
    Returns:
        str: LoRa data or None
    """
    devices = lora_conf.get_devices()
    if devices:
        for i in range(len(devices)):
            data = ntn_dongle.pcie2_cmd('AT+BISGET=?')
            if data:
                print(f'LoRa data: {data}')
                return data
            else:
                print('No LoRa data available')
    return None

def main(lora_setup_only=False):
    """
    Main function demonstrating NTN dongle usage with LoRa support

    Args:
        lora_setup_only (bool): If True, only perform LoRa setup operations
    """
    if lora_setup_only:
        print('=== LoRa Setup Demo ===')
    else:
        print('=== Pico NTN Modbus Master with LoRa Demo ===')

    # Configuration for Pico-2CH-RS485
    # Adjust these parameters based on your specific board configuration
    SLAVE_ADDRESS = 1
    UART_ID = 1
    TX_PIN = 4  # GP4 for UART1 TX
    RX_PIN = 5  # GP5 for UART1 RX
    BAUDRATE = 115200
    CTRL_PIN = None  # Set to appropriate pin if DE/RE control is needed

    try:
        # Initialize NTN Modbus Master
        ntn_dongle = ntn_operation(
            slave_address=SLAVE_ADDRESS,
            uart_id=UART_ID,
            tx_pin=TX_PIN,
            rx_pin=RX_PIN,
            baudrate=BAUDRATE,
            ctrl_pin=CTRL_PIN,
            lock=_thread.allocate_lock()
        )

        # Setup device password
        if not ntn_dongle.setup_device_password():
            print('Failed to setup device password')
            return

        # Initialize LoRa configuration
        print('\n=== LoRa Configuration ===')
        lora_conf = LoraConfig()

        # Configure LoRa parameters
        lora_conf.set_lora_params(frequency='923200000', sf='9', ch_plan='0')

        if lora_setup_only:
            # === Setup LoRa devices (privare key) here ===
            # Example device configuration (replace with actual values)
            #lora_conf.add_device('device1', '0:002f2ebb:2b7e151628aed2a6abf7158809cf4f3c:2b7e151628aed2a6abf7158809cf4f3c')

            # === Setup public key here ===
            # Example public key (replace with actual value)
            # lora_conf.set_pubkey('0123456789abcdef0123456789abcdef:fedcba9876543210fedcba9876543210')

            print('\n=== LoRa Module Setup ===')
            # Setup LoRa module with desired parameters
            setup_lora(ntn_dongle, lora_conf,
                      setup_module=True,      # Configure LoRa parameters
                      setup_privkeys=True,   # Set to True to configure private keys
                      cleanup_privkeys=False, # Set to True to clear private keys
                      setup_pubkey=False,     # Set to True to configure public key
                      cleanup_pubkey=False)   # Set to True to clear public key

            #print('\n=== LoRa Private Key Query ===')
            # Query current private keys
            #lora_privkey_query(ntn_dongle, num_devices=16)

            print('LoRa setup demo completed')
            return

        # === Setup LoRa devices (privare key) here ===
        # Example device configuration (replace with actual values)
        #lora_conf.add_device('device1', '0:002f2ebb:2b7e151628aed2a6abf7158809cf4f3c:2b7e151628aed2a6abf7158809cf4f3c')

        # === Setup public key here ===
        # Example: Set public key (optional)
        # lora_conf.set_pubkey('2b7e151628aed2a6abf7158809cf4f3c:2b7e151628aed2a6abf7158809cf4f3c')

        # Get IMSI information
        print('\n=== IMSI Information ===')
        imsi = ntn_dongle.get_imsi()
        if not imsi:
            print('Failed to get IMSI, exiting')
            return

        # Get device information
        print('\n=== Device Information ===')
        device_info = ntn_dongle.get_device_info()

        print('\n=== Network Information ===')
        network_info = ntn_dongle.get_network_info()

        # Start downlink monitoring in background thread
        if not ntn_dongle.start_downlink_monitor():
            print('Warning: Failed to start downlink monitor')

        # Main loop
        print('\n=== Starting main monitoring loop ===')
        try:
            loop_count = 0
            while True:
                try:
                    # Check device status
                    status = ntn_dongle.get_device_status()
                    if status:
                        print(f'\nDevice Status: {status}')

                        if status['all_ready'] and ntn_dongle.is_upload_avaliable():
                            print('Device is ready for communication')
                            network_info = ntn_dongle.get_network_info()
                            print(f'Network Info: {network_info}') 
                            # Example: Send network infomation
                            s_data = {
                                'c': [network_info['rsrp'], network_info['sinr']],
                            }
                            response = ntn_dongle.send_uplink_data(s_data)
                            if response:
                                print(f'Uplink successful: {response}')
                        else:
                            print('Device not ready for communication')

                        # Check for LoRa data every few loops
                        if loop_count % 3 == 0:  # Every 3rd iteration
                            print('\n=== Checking LoRa Data ===')
                            lora_data = lora_get_data(ntn_dongle, lora_conf)
                            if lora_data:
                                print(f'LoRa data received: {lora_data}')
                    loop_count += 1
                    # Wait before next iteration
                    time.sleep(600)  # Check every 10 minute
                except KeyboardInterrupt:
                    print('\nStopping...')
                    break
                except Exception as e:
                    print(f'Error in main loop: {e}')
                    time.sleep(10)
        finally:
            ntn_dongle.stop_downlink_monitor()
            # Ensure threads are stopped when exiting
            print('Cleaning up...')

    except Exception as e:
        print(f'Failed to initialize: {e}')

def demo_lora_setup():
    """
    Demonstration function for LoRa setup operations
    Call this function separately to configure LoRa settings
    """
    main(lora_setup_only=True)

# === Configuration for Pico Execution ===
# Set this to True to run LoRa setup only mode
# You can change this before uploading to Pico
RUN_LORA_SETUP_ONLY = False

if __name__ == '__main__':
    # For Pico/MicroPython execution
    try:
        # Try to use command line arguments (works on some MicroPython implementations)
        lora_setup_only = RUN_LORA_SETUP_ONLY
        if hasattr(sys, 'argv') and len(sys.argv) > 1:
            if sys.argv[1].lower() in ['lora_setup', 'lora', 'setup']:
                lora_setup_only = True
                print('Running LoRa setup mode from command line argument')
            elif sys.argv[1].lower() in ['help', '-h', '--help']:
                print('Usage: python pico_ntn_modbus_master.py [lora_setup]')
                print('  lora_setup: Run only LoRa setup operations')
                print('  (no argument): Run full NTN monitoring demo')
                print('  Or set RUN_LORA_SETUP_ONLY = True at top of file')
                sys.exit(0)
    except:
        # Fallback for MicroPython implementations without full sys.argv support
        lora_setup_only = RUN_LORA_SETUP_ONLY
        print(f'Running in {"LoRa setup" if lora_setup_only else "full demo"} mode')

    main(lora_setup_only=lora_setup_only)
