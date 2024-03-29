# TheCork

Restaurant reservation made easy with *TheCork*! 

## General Information

Customers can display a list of restaurants available at their location and are able to book a table for a specific number of people if the restaurant still has free tables. 
TheCork also provides back-office for the restaurants which is used to manage the schedule and to approve or deny the customers reservations.

The focus lies upon implementing a custom protocol for an authentication server. The protocol is based on MS-CHAPv2 and looks as follows:

![Network Overview](./protocol_details.png)

### Built With

*Python* is used as primary programming language. The API Server is implemented using the *Flask* web framework which is a Python module that lets you develop web applications easily. The database server is running with *MySQL server* and the queries are performed by *SQL-Alchemy*. 

* [Python](https://www.python.org/) - Programming Language and Platform
* [Flask](https://flask.palletsprojects.com/en/2.2.x/) - Web Application Framework
* [SQLAlchemy](https://www.sqlalchemy.org/) - Database Management Framwork

![Network Overview](./network_overview.png)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

**For Testing purposes**: One Linux machine running with Ubunu 20.04 or higher.

**For Deployment**: Four seperate virtual machines running with Ubuntu 20.04 or higher

### Deployment (for testing purposes)

First, execute the following two commands in you console:

```sh
$ export FLASK_APP=TheCork
$ export FLASK_DEBUG=True
```

Then, navigator to the parent folder of this project and run:

```bash
$ flask run
```

### Deployment (for production purposes)

Originally, project requires four seperate virtual machines running Ubuntu 20.04. 
The following paragprah details how to set up these virtual machines

#### **Virtual Machine 1** (External Machine):

* Assign the IP address 192.168.0.100 to network adapter `enps03`:

```bash
$ sudo ifconfig enp0s3 192.168.0.100/24 up
$ sudo /etc/init.d/network-manager force-reload
```

* Set VM2 as default gateway:

```bash
$ sudo ip route add default via 192.168.0.10 
```

From this external machine, you are able to access the website which will be set up one the other virtual machines.

#### **Virtual Machine 2** (Screening Router):

* Assign the IP address 192.168.0.10 to network adapter `enps03`, 192.168.1.254 to `enps08` and 192.168.2.254 to `enps09`:

```bash
$ sudo ifconfig enp0s3 192.168.0.10/24 up
$ sudo ifconfig enp0s8 192.168.1.254/24 up
$ sudo ifconfig enp0s9 192.168.2.254/24 up
$ sudo /etc/init.d/network-manager force-reload
```

* Activate Port Forwaring:

```bash
$ sudo sysctl net.ipv4.ip_forward=1
```

* Configure the firewall with the following commands:

```bash
$ sudo iptables -P INPUT DROP
$ sudo iptables -P FORWARD DROP

$ sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$ sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

$ sudo iptables -A FORWARD -p tcp -d 192.168.1.1 --dport 443 -j ACCEPT
$ sudo iptables -A FORWARD -p tcp -d 192.168.1.1 --dport 80 -j ACCEPT
$ sudo iptables -A FORWARD -p tcp -s 192.168.1.1 -d 192.168.2.15 --dport 3306 -j ACCEPT


$ sudo iptables -t nat -A PREROUTING -i enps03 -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1
$ sudo iptables -t nat -A PREROUTING -i enps03 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1
```

#### **Virtual Machine 3** (API Server):

* Assign the IP address 192.168.1.1 to network adapter `enps03`:

```sh
$ sudo ifconfig enp0s3 192.168.1.1/24 up
$ sudo /etc/init.d/network-manager force-reload
```

* Set VM2 as default gateway:

```zsh
$ sudo ip route add default via 192.168.1.254 
```

* Install Apache2:

```console
$ sudo apt update
$ sudo apt install apache2
```

* Add [this configuration file](apache_files/webapp2.conf) to the folder `/etc/apache2/sites-available`. Within the *.conf file* you have to modify the paths to match your setup.

* Within the folder `var/www/` add a folder called *TheCork*. In this folder you can add this project folder and rename it to *TheCork*. Additonally, add [this file](apache_files/webapp2.wsgi) and again, modify the paths accordingly. You can verify that everything is setup correctly by running:

```bash
$ sudo apache2ctl configtest
```

* Activate the website by running the following command in the terminal:

```bash
$ sudo a2enmod ssl                # Activate SSL Engine
$ sudo a2ensite thecork.conf      # Activate Website
$ sudo systemctl reload apache2   # Reload Apache
```

* Right now, the standard setting is still configured such that it creates a local database. After configuring the Database Server as described in the next step, change the code in __init__.py in line 57-58 as follows:
```python
57 # SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'database.db'),
58 SQLALCHEMY_DATABASE_URI = 'mysql://arne:pwdarne0!@192.168.2.15/TheCork',
```

* Now, you should be able to call the website in the browser of your choice (tested on Firefox) under the IP address `192.168.1.1:443` (at least if you already set up the Database Server as detailed in the next paragraph)

#### **Virtual Machine 4** (Database Server):

* Assign the IP address 192.168.2.4 to network adapter `enps03`:

```
sudo ifconfig enp0s3 192.168.2.4/24 up
sudo /etc/init.d/network-manager force-reload
```

* Set VM2 as default gateway:

```
$ sudo ip route add default via 192.168.2.254 
```

* Install MySQL-Server and start the server:
```
$ sudo apt install mysql-server
$ sudo systemctl start mysql.service
```

* Adjust how your root MySQL user authenticates to avoid an error when running the configuration script:
```SQL
$ sudo mysql
mysql> ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '<your_password>';
mysql> exit
```

* Now configure the security. Go through this guided questionaire step by step:
```
$ sudo mysql_secure_installation
```

* After that being done, you can add a user for your API server to communicate with the database:
```SQL
$ sudo myslq -u root -p
mysql> CREATE USER 'thecork'@'192.168.1.1' IDENTIFIED BY '<your_password>';
mysql> CREATE DATABASE thecork
mysql> GRANT ALL PRIVILEGES ON thecork.* TO 'thecork'@'192.168.1.1';
```

* In case something does not working, you can try restarting MySQL ith the following command:
```
$ sudo /etc/init.d/mysql restart
```

The rest (creating and querying the database) is automatically done by the SQL-Alchemy framework when running the website.

## Additional Information

### Hashes of VMs:

The hashes of the VMs have been created using `sha256sum` for the snapshots-files of kind *.vdi* and the VirtualBox files of kind *.vbox*

### Author: 
**Arne Grobrügge** 

See also the list of [contributors](https://github.com/grobruegge/sirs2023/contributors) who participated in this project.
