import machine
import network
import time
import mip
station = network.WLAN(network.STA_IF)
station.active(True)
# Set your WiFi SSID and password here
station.connect(SSID, password)
time.sleep(1)
while not station.isconnected():
    print('Connecting to network...')
    time.sleep(1)
print('Device connected to network: {}'.format(station.isconnected()))
# put package to install to Pico W below
mip.install('github:brainelectronics/micropython-modbus')
print('Installation completed')
machine.soft_reset()