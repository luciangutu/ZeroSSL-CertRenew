# ZeroSSL-CertRenew
A Python script that automatically renews the certificate on ZeroSSL.


Requirements:
- certificates are stored under /etc/ssl/certs/
- www-root/DocumentRoot is stored in /var/www/<domain.com>/web/ and the certificates are under /var/www/<domain.com>/ssl/
- Python 3

OpenSSL is used to create the private key and csr.

There is no exception handling anywhere in the code, so things might not be stable.

Execute the script with

	$ python3 ZeroSSL_CertRenew.py -h
	# systemctl reload apache2
	
