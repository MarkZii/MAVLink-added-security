# MAVLink-added-security
This project analyzes MAVLink vulnerabilities. It proposes a secure implementation using symmetric encryption (AES, ChaCha20) for confidentiality and ECDH for dynamic key management. Tests on Raspberry Pi 4 show ChaCha20, secp256r1 and secp384r1 is the best balance for resource-limited drones

# Usage
if you want to run this project you will need to:
 - Install the MAVLink protocol on your Linux machine following this [guide](http://mavlink.io/en/getting_started/installation.html).
 - Definition af the "secure" dialect illustrated on the page 35 of the report.

To use the "secure" dialect it is important to follow these steps:
 - Save the `secure.xml` in the folder `message_definitions/v1.0`. Then, execute the following command: `python3 -m pymavlink.tools.mavgen --lang=Python3 --wire-protocol=2.0 --output=include/mavlink message_definitions/v1.0/secure.xml`
 - Copy the generated `.py` file into the appropriate folder: 
    - MAVLink 2: `pymavlink/dialects/v20`
    - MAVLink 1: `pymavlink/dialects/v10`
 - Uninstall any pre-existing version of pymavlink to avoid conflicts: `pip uninstall pymavlink`.
 - Install `pymavlink` along with all its dependencies: `python3 -m pip install -r pymavlink/requirements.txt`.
 - Finally, run the Python setup script: `python3 setup.py install --use`.

Useful links:
 - [Link 1](https://mavlink.io/en/mavgen_python/#getting-the-python-mavlink-libraries).
 - [Link 2](https://mavlink.io/en/getting_started/generate_libraries.html).
