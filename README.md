# WMAT
WMAT is automatic tool for testing webmail accounts. Support SSL pages, have automatic generator for default passwords. XML driven patterns.

Web Mail Auth Tool

= About:

WMAT is automatic tool for testing webmail accounts.
Support SSL pages, have automatic generator for default passwords.
XML driven patterns.



= Usage:

-u usernames_file required (except in passsorter mode)
-p passwords_file required (except in passsorter mode)
-t timeout in seconds !required
-w output_file !required
--url Webmail URL required
--pattern pattern_xml required
--bell Bell on success !required
--proxy Proxy[IP:PORT] !required"
--proxyup Proxy UP [username:password] !required
--passsorter File or Email address !required



= Examples:

python wmat.py -u usernames_example.txt -p passwords_example.txt --url webmail.domain.tld --pattern patterns/dummy.wmat.xml

- Basic example


python wmat.py -u usernames_example.txt -p passwords_example.txt --url webmail.domain.tld --pattern patterns/dummy.wmat.xml --bell -w output_file.txt

- Use bell and write output to file


python wmat.py -u usernames_example.txt -p passwords_example.txt --url webmail.domain.tld --pattern patterns/dummy.wmat.xml --proxy xxx.xxx.xxx.xxx:8080 --proxyup username:password\n"

- Use proxy with username and password


python wmat.py --passsorter usernames_example.txt --url webmail.domain.tld --pattern patterns/dummy.wmat.xml --bell -t 5\n"
    
- Use passsorter engine with bell and timeout 5 sec    
    


= Tips

- If You give url with https prefix, engine will switch to SSL mode
- Passsorter option generate simple passwords from given username(s)
- Must have temp_cookie.txt in the same folder
- Use [amp] instead & in XML files


= Contact: 

Ivan Markovic, ivanm@security-net.biz, http://security-net.biz/

* You can contribute to this tool by sending new patterns



