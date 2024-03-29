# Script-phishing

The purpose of this *Bash* script is to configure a server to make it a Phishing server.
It is done by installing and configuring automatically some tools :

- [**Postfix**](http://www.postfix.org/)
- [**OpenDKIM**](http://www.opendkim.org/)
- [**OpenDMARC**](https://github.com/trusteddomainproject/OpenDMARC)
- [**GoPhish**](https://github.com/gophish/gophish)

To use it, make it executable and run it as root or as a user present the sudo group : 
```
chmod +x serversetup.sh
sudo ./serversetup.sh
```
When running it, you will first land on a menu with 8 options that each correspond to a specific function of the script.

The script also proposes to change the hostname of the server or to configure the firewall.

You can also directly generate Let's Encrypt certificates with [Certbot](https://github.com/certbot/certbot) that will be used for the mail server but also for your [GoPhish website](https://docs.getgophish.com/user-guide/installation).

One of its coolest aspects is that it directly gives the necessary informations for the correct DNS configuration to make on your DNS page (Cloudflare, OVH etc...) in order to make the mail server work correctly (*SPF*, *DKIM*, *DMARC* ...).

If you want to test your mail server, I encourage you to use some online and free tools like [mail-tester](https://www.mail-tester.com/) (*really helpful !*), [DKIM Checker](https://dmarcian.com/dkim-inspector/), [DMARC Checker](https://dmarcian.com/dmarc-inspector/).

As said above you still have some manual stuff to do like DNS configuration and the [GoPhish configuration on the admin panel](https://docs.getgophish.com/user-guide/) to launch a phishing campaign but the main goal of this script is to automate as much as possible the configuration of a phishing server.

I hope you gonna catch many fishes :smiley: :fish: