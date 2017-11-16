# SPRESSO Test Environment #

This document describes the installation of SPRESSO on an Ubuntu 14.04 system. The test system will use the Test SSL Certificates that come with the Apache server. This description assumes that server and client are running on the same machine.

## Basic structure ##

The system consists of three servers written in Node.js: the relying party (RP), the forwarder (FWD), and the identity provider (IdP). These servers will open a dedicated port which serves HTTP. We use Apache as a proxy in front of these servers that will serve HTTPS and forward all requests (depending on the domain) to the respective Node.js server.

## Requisites ##

Set up Chris Lea's node.js-devel PPA in your system (it contains Node.js version 0.11.15 which is not the newest version, but sufficient). Node.js 0.10 which is contained in the Ubuntu repositories is *not* working correctly regarding AES-GCM mode.

    sudo apt-add-repository ppa:chris-lea/node.js-devel
    sudo apt-get update

Install apache2 and Node.js (with cookie module):

    sudo apt-get install apache2 nodejs node-cookie

## Set up Apache server ##

Copy the files rp-ssl.conf, fwd-ssl.conf and idp-ssl.conf from the example-config subdirectory to /etc/apache2/sites-available and enable them in apache:

    sudo cp rp-ssl.conf fwd-ssl.conf idp-ssl.conf /etc/apache2/sites-available
	sudo a2ensite rp-ssl
	sudo a2ensite fwd-ssl
	sudo a2ensite idp-ssl

Enable necessary ssl modules in Apache:

	sudo a2enmod ssl
	sudo a2enmod proxy
	sudo a2enmod proxy_http
	sudo service apache2 restart

Set up local name resolution for the test domains test1, test2, test3. Edit /etc/hosts and add the test domains to localhost:

	...
	127.0.0.1 localhost test1 test2 test3
	...

## Start SPRESSO servers ##

Open three terminals, one for each service (rp, fwd, idp), and `cd` into the respective source directory. Then, in each terminal, run `nodejs server.js`.

## Using the SPRESSO test system ##

Open a web browser and browse to the following URLs and accept the SSL certificate warning (remember that we are just using the default test certificate here):

 * https://test1/ (RP)
 * https://test2/ (IdP)
 * https://test3/ (FWD)


