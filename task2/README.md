
# Task 2 - Extract the Firmware - (Hardware analysis, Datasheets)Points: 100

```
Thanks to your efforts the USCG discovered the unknown object by trilaterating the geo and timestamp entries of their record with the correlating entries you provided from the NSA databases. Upon discovery, the device appears to be a device with some kind of collection array used for transmitting and receiving. Further visual inspection shows the brains of this device to be reminiscent of a popular hobbyist computer. Common data and visual ports non-responsive; the only exception is a boot prompt output when connecting over HDMI. Most interestingly there is a 40pin GPIO header with an additional 20pin header. Many of these physical pins show low-voltage activity which indicate data may be enabled. There may be a way to still interact with the device firmware...

Find the correct processor datasheet, and then use it and the resources provided to enter which physical pins enable data to and from this device

Hints:

The pinout.svg has two voltage types. The gold/tan is 3.3v, the red is 5v.
The only additional resource you will need is the datasheet, or at least the relevant information from it

Downloads:

Rendering of debug ports on embedded computer (pinout.svg)
image of device CPU (cpu.jpg)
copy of display output when attempting to read from HDMI (boot_prompt.log)


Provide the correct physical pin number to power the GPIO header:
Provide a correct physical pin number to ground the board:
Provide the correct physical pin number for a UART transmit function:
Provide the correct physical pin number for a UART receive function:
```


For this task I pretty much just looked at the cpu picture and found `BCM2837-Broadcom.pdf` online.

[cpu.jpg](cpu.jpg)

[pinout.svg](pinout.svg)

Based on the picture, the cpu was a `BCM2837` arm system-on-chip.
Based on the `boot_prompt.log` file, the system is in `ALT5` function mode.

Something very important to note with this task is that `GPIO Pin # != Physical Pin #`.

After looking at the datasheet and questions, I picked out all of the rows in the "Alternative Function Assignments Table" with any functionality related to uart

Special function legend (relevant parts):

|Name| Function |
|----|----------|
|TXD0| UART 0 Transmit Data|
|RXD0| UART 0 Receive Data|

The actual table went from GPIO0-GPIO53, but I have removed most of the irrelevant data.

Alternative Function Assignments Table:

|GPIO # |Pull|ALT0|ALT1|ALT2|ALT3| ALT4| ALT5|
|-------|----|----|----|----|----|-----|-----|
|GPIO14|Low|TXD0|SD6|<reserved>|||TXD1|
|GPIO15|Low|RXD0|SD7|<reserved>|||RXD1|
|GPIO16|Low|<reserved>|SD8|<reserved>|CTS0SPI1_CE2_N|CTS1|
|GPIO17|Low|<reserved>|SD9|<reserved>|RTS0SPI1_CE1_N|RTS1|
|GPIO18|Low|PCM_CLK|SD10|<reserved>|PWM0|
|GPIO19|Low|PCM_FS|SD11|<reserved>|SPI1_MISO|PWM1|
|GPIO20|Low|PCM_DIN|SD12|<reserved>|SPI1_MOSI|GPCLK0|
|GPIO21|Low|PCM_DOUT|SD13|<reserved>|SPI1_SCLK|GPCLK1|
|GPIO32|Low|GPCLK0|SA1|<reserved>|TXD0||TXD1|
|GPIO33|Low|<reserved>|SA0|<reserved>RXD0||RXD1|
|GPIO40|Low|PWM0|SD4||<reserved>|SPI2_MISO|TXD1|
|GPIO41|Low|PWM1|SD5|<reserved>|<reserved>|SPI2_MOSI|RXD1|


Based on this table, I was able to narrow down my options for the GPIO questions. In `ALT5` mode, 14, 32, and 40 are UART `TXD1`, 15, 33, and 41 are UART `RXD1`. The pairs of options for TX and RX are (14 & 15) (32 & 33) (40 & 41).

Looking at the pinout diagram provided, only one of those pairs is actually present, that being GPIO32 and GPIO33 on physical pins P37 and P38.


I wasn't really certain which of the pins marked `voltage` were correct, nor what the different colors of pins actually meant. In retrospect yellow pins are probably low pull and red are probably high pull. Regardless, there were only 3 yellow and 2 red `voltage` pins and only 3 ground pins, so i tried a few different combinations until it worked.

```
Provide the correct physical pin number to power the GPIO header: P17
Provide a correct physical pin number to ground the board: P14
Provide the correct physical pin number for a UART transmit function: P37
Provide the correct physical pin number for a UART receive function: P38
```

