# 42 Common Core / Born2BeRoot

This project consists in setting up a server in a virtual machine, using Virtual Box, under specific instructions.
The operating system chosen was the latest stable version of ***Debian***, at the time (bullseye 11.7.0).

### Requirements for the mandatory part
- Partitioning using ***LVM*** and according to specified definitions (different with or without bonus part);
- Install and configure ***sudo*** following strict rules:
  - authentication using sudo has to be limited to 3 attempts in the event of an incorrect password;
  - a custom message has to be displayed if an erros due to a wrong password occurs when using sudo;
  - each action using sudo has to be archived, both inputs and outputs. The log file has to be saved in the /var/log/sudo/ folder;
  - TTY mode has to be enabled for security reasons;
  - the paths that can be used by sudo must be restricted to: /usr/local/sbin:/user/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin 
- Install and configure ***SSH*** only running on 4242;
- Install and configure ***UFW*** firewall;
- Implement a strong password policy for existing and new users using ***libpam-pwquality*** package:
  - password has to expire every 30 days;
  - minimum number of days allowed before the modification of a password will be set to 2;
  - the user has to receive a warning message 7 days before their password expires;
  - password must be at least 10 characters long, contain an uppercase letter, a lowercase letter, and a number;
  - password must not contain more than 3 consecutive identical characters;
  - password must not include the name of the user;
  - password must have at leas 7 characters that are not part of the former password (does not apply to the root password);
- Set up a ***cron*** job with a monitoring script that displays some system info on all terminals every 10 minutes;

### Requirements for the bonus part:
- Set up a functional ***WordPress*** website using the following services: ***lighttpd***, ***MariaDB*** and ***PHP***;
- Set up an aditional service. In this case I installed ***FTP*** and ***ShellGPT*** (command line version of ChatGPT);

## Installation
The initial steps to install ***Debian*** can be found in several tutorials across GitHub and Youtube so I won't detail it here. However I will specify how to correctly partition the disk so we can get the same values when using the `lsblk` command as showed in the project subject.

<img width="769" alt="image" src="https://github.com/josevazf/42-Born2BeRoot/assets/19204122/f0786d7e-f06b-4444-ad2c-2dc3236b68d7">

When we are defining the size for the partitions we are working with Gigabyte wich is Decimal units, however what we see when using the `lsblk` command is Gibibyte, which is Binary.
We need to convert the Gibibyte values to aproximate Gigabyte values. To do that we can use this online [Converter]([https://pages.github.com/](https://www.dataunitconverter.com/gigabyte-to-gibibyte)).

<img src="https://github.com/josevazf/42-Born2BeRoot/assets/19204122/a387287b-5e60-4538-a73b-ff19fe90aabe">

`lsblk` - prints all block devices (except RAM disks) in a tree-like format by default

## Sudo, Groups & Hostname

`su -` (substitute user) - login to the root account

`apt update`

`apt upgrade`

`apt install sudo` - install the sudo package that grants root privileges to users

`dpkg -l | grep sudo` - verify if sudo was successfully installed

`adduser <username> <groupname>` - add user to group 

`sudo deluser <username> <groupname>` - delete user from group 

`getent group <groupname>` - view users in sudo group

`sudo groupadd <groupname>` - create a new group 

`sudo groupdel <groupname>` - delete a group
It is not possible to remove the primary group of an existing user without removing the user first. The command above removes the group entry from the `/etc/group` and `/etc/gshadow` files.

`id -g <username>` - displays a user’s main group ID

`cat /etc/passwd | cut -d ":" -f 1`  - displays a list of all users on the machine

`cat /etc/passwd | awk -F '{print $1}'`  - same as above

`sudo hostnamectl set-hostname <new_hostname>` - change hostname

`hostnamectl status` - check hostname status

`sudo visudo -f /etc/sudoers.d/newsudorules` - Opening sudo files with "visudo" creates a safer structure, we created a new file called `newsudorules` in the specified directory and we will add the following codes:

`Defaults		passwd_tries=3` 
*With Sudo, the maximum number of password attempts is 3 (3 is also standard)*

`Defaults		badpass_message="Incorrect Password"`
*Your error message after incorrect password attempts*

`Defaults		logfile="/var/log/sudo/newsudo_log"`
*Stores all used sudo commands in the specified file*

`Defaults		log_input,log_output`
*It is used to keep logs of inputs and outputs.*

`Defaults		iolog_dir="/var/log/sudo"`
*Archive log_input and log_output events to the specified directory.*

`Defaults		requiretty`
*Enforces TTY mode.*

`Defaults		secure_path="see bellow"`

`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin`
*To limit the directories used by Sudo.*

## SSH & UFW

Openssh provides a secure channel over an unsecured network from the outside

`sudo apt install openssh-server` - installs the openssh-server package

`sudo service ssh status` or `sudo systemctl status ssh` - view the SSH status

`sudo vim /etc/ssh/sshd_config` - opens the SSH config file:

Change `Port 22` to `Port 4242`

Change `PermitRootLogin prohibit-password` to `PermitRootLogin no`

`sudo systemctl restart ssh` - restart ssh service

`sudo apt install ufw` - install “Uncomplicated Firewall”

`sudo ufw status` - check status of firewall

`sudo ufw enable` - enable firewall

`sudo ufw allow <port>` - we add a new rule for our firewall to allow port

`sudo ufw deny <port>` - remove rule to allow port

`sudo ufw delete allow <port>` - remove port allow rule

`sudo ufw delete deny <port>` - remove port deny rule

`sudo ufw status numbered`

`sudo ufw delete <port index>`

`sudo ip address` - check ip address

192.168.1.82

Change Network adapter to `Bridged Adapter`

Lock ip address (check ip address on previous command) : `10.11.248.140`

`sudo nano /etc/network/interfaces` - opens the interfaces file describer:

> #The primary network interface
****`auto enp0s3
iface enp0s3 inet static
address 10.11.248.140
netmask 255.255.0.0
gateway 10.11.254.254
dns-nameservers 10.11.254.254`
> 

## Password Policy

`sudo vim /etc/login.defs` - we define some conditions on the time validity of passwords:

`PASS_MAX_DAYS 30` - maximum number of days a password may be used

`PASS_MIN_DAYS 2` - minimum number of days allowed between password changes

`PASS_WARN_AGE 7` - number of days warning given before password expires

`chage -l <username>` - check password condition

`sudo chage -M 30 <username>`

`sudo chage -m 2 <username>`

`sudo chage -W 7 <username>`

Must be done for each user and root!

`sudo apt install libpam-pwquality` - install the libpam-pwquality package to increase the security of passwords

`sudo vim /etc/pam.d/common-password` - open document and add after password requisite pam_pwquality.so 

`sudo nano /etc/security/pwquality.conf` - open and edit

`difok = 7` - number of characters that must not be present in the old password

`retry=3` - prompt user at least 3 times before returning error

`minlen=10` - minimum size for the new password

`dcredit=-1` - minimum digit number 

`ucredit=-1` - minimum uppercase character

`lcredit=-1` - minimum lowercase character

`maxrepeat=3` - maximum number of consecutive same characters

`usercheck=1` - check if it contains the username in the password

`enforce_for_root` - enforces pwquality checks on the root user password

`passwd username` - change password

## Monitoring Script (cron)

https://www.geeksforgeeks.org/crontab-in-linux-with-examples/

`sort` = alphabetical sorting.
`uniq` = separating repeating lines.
`$1,$2...` = We can say that Mer $1, haba $2, yesterday $3 or $4 columns are holding.
`free -m` = It shows the amount of Ram in Mebibytes. The reason for doing so is to calculate the percentage over the uses of the script, etc. for us to do.
`grep '^/dev/'` = ^ takes the places starting with the word after the suffix.
`grep -v '/boot$'` = -v The suffix indicates the word to be extracted
`awk '{ft += $2} END {print ft}'` = ft It can be thought of as a variable, it adds the data contained in $2 in ft and prints ft to the screen.
`cut -c 9- | xargs | awk '{printf("%.1f%%")` = "cut -c 9-" Used to delete a character or a sequence of characters. "xargs" As a function, it forwards the previously used output to the next command. `"printf("%.1f%%%")"` Takes 1 character after "." in float value type and adds "%" at the end.

`uname -a` - prints all architecture information, except if the CPU is unkown
`grep “physical id” /proc/cpuinfo | wc -l` - number of fisical cores obtained from the file in the directory. We count the lines with `wc -l` 
`grep processor /proc/cpuinfo | wc -l` - show the number of virtual cores

`free —mega | awk '$1 == "Mem:" {print $3}'` - see information about ram, measured in mb. We use awk t process the data. Comparing if the first word of a row is equal to “Mem:” we print the third word of that row, which will be the used memory

Cron is located under `/etc/init.d`

`sudo vim /root/monitoring.sh` - create and open monitoring script file

”PASTE CONTENTS”

`sudo chmod 777 monitoring.sh` - give full permissions to the monitor script file

`sudo systemctl status cron` - check if cron is active

`sudo systemctl enable cron` - enable cron

`sudo crontab -e` - add the job to cron

`*/10 * * * * bash /root/monitoring.sh` - will execute every 10 minutes

`sudo crontab -u root -l` - check root’s scheduled cron jobs

> `/etc/init.d/cron stop` - stop cron service
`/etc/init.d/cron start` - start cron service
> 

## Bonus

`service —status-all` - check services

`ss -tunlp` - check ports and ip

### Lighttpd & PHP

Lighttpd is a HTTP web server designed to be fast, secure, flexible and standards-compliant

`sudo apt install lighttpd` - install lighttpd

`sudo ufw allow 80` - port 80 Standard port for HTTP

`dpkg -l | grep lighttpd` - check if lighttpd is installed

`sudo lighttpd -v` - check version

Check if apache2 was installed:

`systemctl status apache2`

`sudo apt purge apache2`

`sudo systemctl start lighttpd` - start lighttpd

`sudo systemctl enable lighttpd` - enable lighttpd

`sudo systemctl status lighttpd` - check lighttpd status

`sudo ufw allow http`

`sudo ufw status`

Port forwarding VM, new rule, host port `8080` to foward to guest `80`

Test with: https://127.0.0.1:8080 or http://localhost:8080

`sudo apt install php-cgi php-mysql`

> `sudo lighty-enable-mod fastcgi
sudo lighty-enable-mod fastcgi-php` 
`sudo service lighttpd force-reload`
> 

Create a file in `/var/www/html` named `info.php` and write:

```php
<?php
phpinfo();
?>
```

Test with: [http://127.0.0.1:8080/info.php](https://127.0.0.1:8080/info.php) or http://localhost:8080

### MariaDB

MariaDB is a database used for various purposes, such as data storage, e-commerce, logging apps, etc.

`sudo apt install mariadb-server` - install MariaDB

Because the default configuration leaves your MariaDB installation unsecure, we will use a script provided by the mariadb-server package to restrict access to the server and remove unused accounts:
`sudo mysql_secure_installation`

 It will ask the following:

`Switch to unix_socket autentication? → N
Change the root password? → N
Remove anonymous users? → Y
Disallow root login remotely? → Y
Remove test database and acces to it? → Y
Reaload privilege tables now? → Y`

`sudo systemctl restart mariadb`

`sudo mariadb` - enter mariadb console

`CREATE DATABASE database;
CREATE USER 'user'@'localhost' IDENTIFIED BY 'WPpassw0rd';
GRANT ALL ON database.* TO 'user'@'localhost' IDENTIFIED BY 'WPpassw0rd' WITH GRANT OPTION;,
FLUSH PRIVILEGES;
EXIT;`

Open MariaDB and login with created user:

`mariadb -u user -p`

`SHOW DATABASES;`

______________________________________________________
DELETE, ALTER, REVOKE USER

`SELECT User, Host FROM mysql.user;` - list al mysql users

`SHOW GRANTS FOR ‘user’@’localhost’;` - list grants for a mysql user

`REVOKE ALL PRIVILEGES, GRANT OPTION FROM ‘user’@’localhost’;` - revoke all grants for q mysql user

`ALTER USER 'user'@'localhost' IDENTIFIED BY 'new_password';` - change password

`DROP DATABASE database;` - delete a database

### WordPress

WordPress is a content management system focused on the creation of any type of website

We must install `wget` and `zip` first:

`sudo apt install wget zip`

`sudo wget http://wordpress.org/latest.tar.gz -P /var/www` - download latest version of WordPress to the /var/www/html folder

`sudo tar -xzvf /var/www/latest.tar.gz` - extract content

`sudo rm /var/www/latest.tar.gz` - delete .tar file

`sudo mv html/ html_old/` - rename html folder to html_old

`sudo mv wordpress/ html/` - rename wordpress folder to html

`sudo chmod -R 755 html` - set permissions to html folder

`sudo cp wp-config-sample.php wp-config.php` - create a copy of sample config file

`sudo vim wp-config.php` - edit the file with mariadb credentials

> Site Title: Born2BeRoot (jrocha-v)
Username: jrocha-v
Password: uIZ*F(H(4I7$^DErC4
> 

http://10.11.248.140/wp-admin/

`apt-get install php-mbstring` (para o kubio plugin)

### VSFTPD (FTP server)sudo crontab -l

File Transfer Protocol (FTP) servers can be useful for providing files to customers and for exchanging files with partners and business associates.

VSFTP is a secure, stable, and fast FTP server. It can greatly decrease the chances of an attacker gaining access to a server via FTP exploits.

`sudo apt install vsftpd`

`dpkg -l | grep vsftpd` - check if it was successfully installed

`sudo ufw allow 21` - open door 21

`sudo ufw status`

`sudo nano /etc/vsftpd.conf` - remove # write_enable=YES and add:

> `user_sub_token=$USER
local_root=/home/$USER/ftp
userlist_enalbe=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO`
> 

`sudo mkdir /home/username/ftp` - open an ftp folder in the directory of our user

`sudo mkdir /home/username/ftp/files` - open the files folder

`sudo chown nobody:nogroup /home/username/ftp` - set the ownership and group to nobody

`sudo nano /etc/vsftpd.userlist` - add 0 and username

To install wordpress themes we use FTP to transfer files to our server

https://www.baeldung.com/linux/ftp-transfers

`sudo apt-get install unzip` - install unzip

In server set all permissions to the /themes folder:

`cd /var/www/html/wp-content
sudo chmod 777 themes`

https://wordpress.org/themes/myself/

In terminal to the original folder where the .zip file was downloaded and login to ftp:

`cd Downloads`

`ftp 10.11.248.140` - username….password….

ftp> `cd /var/www/html/wp-content/themes` - go to destination folder in server
ftp> `binary` - switch to binary transfer
ftp> `put niveau.1.0.5.zip` - copy the file

In the server unzip the file:

`unzip niveau.1.0.5.zip`

Go to wordpress page and install the theme

### ShellGPT

https://beebom.com/how-use-chatgpt-linux-terminal/

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

`python3 —version` - check python version

If an older version of python is installed, upgrade:

`sudo apt —only-upgrade install python3`

If not:

`sudo apt update && sudo apt upgrade -y` - update all packages and repositories

`sudo apt install python3` - install python

Install PIP package manager for python:

`sudo apt-get -y install python3-pip`

`pip3 —version` - check pip version

Install Venv module, to create an isolated virtual environment in Linux and prevent any conflict with other libraries. Installing any library or package will install many background dependencies that can interfere with other libraries. To create a virtual environment for a project, you need the “venv” module, which can be installed using the command below:

`sudo apt install python3-venv`

Go to root:

`mkdir cmdline-chatgpt` - create a directory

Enter the created directory and create a virtual environment:

`python3 -m venv chatgpt_cli`

`source chatgpt_cli/bin/activate` - activate virtual environment

Get OpenAI API key:

`export OPEN_API_KEY=<key>` - create an environment variable for this API key

`env` - verify by listing it

This variable is temporarily stored for the current session so we need to export it into a .bashrc file:

`export OPENAI_API_KEY=<key>`

`source .bashrc` - confirm changes

`env` - verify by listing.

Install ShellGPT:

`pip3 install shell-gpt —user` - ommit `—user` if installing in a virtual environment

Syntax and options to use

`source .bashrc`

`sgpt <options> <input_query>`

| --temperature | Changes the randomness of the output |
| --- | --- |
| --top-probablity | Limits to only the highest probable tokens or words |
| --chat | Used to have a conversation with a unique name |
| --shell | Used to get shell commands as output |
| --execute | Executes the commands received as output from --shell option |
| --code | Used to get code as output |
