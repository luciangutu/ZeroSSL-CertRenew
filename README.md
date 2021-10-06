# ZeroSSL-CertRenew
A python script that automatically renews the certificate on ZeroSSL

The script assumes that certificates are stored under /etc/ssl/certs/
The script assumes that the www-root is stored in /var/www/<domain.com>/

OpenSSL is used to create the private key and csr.

There is no exception handling anywhere in the code, so things might not be stable.

Execute the script with

	python3 ZeroSSL_CertRenew.py -h
