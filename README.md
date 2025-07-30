<img width="1133" height="306" alt="PyNmap2" src="https://github.com/user-attachments/assets/4e97ddb4-446c-4ac6-b1c9-9ee6a55b1b58" />


NMAP Client in Python, with a Interactive menu, allowing for easy scanning of IPs - Domains, Exportable history to JSON or CSV file.
Requires NMAP to be installed on current system
Use Package Manager in Linux (APT, Yum, Pacman, Yay, DNF, ect ect

```sudo apt-get install nmap```

Only tested on Python 3.13 via Blackarch Linux thus far but it requires venv so it should work on any OS

``` pip install -r requirements.txt```
``` python -m venv /path/to/PyNmap/```
``` source /path/to/PyNmap/bin/activate ```


Most Port scanning options require Sudo, or root elevation.

from inside the working directory run 

```python __main__.py```

If you have any issues, or would like to add or improve this project dont hesitate to submit a issues post or a pull request.
