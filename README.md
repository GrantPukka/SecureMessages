Secure-messaging is just a fun application I have made that is designed to be deployed and used in the CLI.  It has some interesting features file encryption and decryption as well as encrypted messaging.
I am a complete novice so there will 100% be alot of errors and functional improvements that could make it better please suggest away.
I do want to include an offline messaging option where messages get encoded as encrypted QR codes and can only be decrypted by the end user.  Help would be great.
I would also like to eventually have this application with a user friendly front-end webinterface and potentially a mobile application.
Additional features would also be welcome
Initial set-up is a little confusing.
quick-setup
  choose if you are a client, field server or static server (set-up clients first until it prompts for server set-up then set-up your servers)
    export .pem files to a USB and rename the **my** to **import** for clients at the end of the exported .pem label it **c1 or whichever number client you are** dont delete any other words other than my
    all other points to export .pem files the name can remain the default on the usb and when it is imported on the trusted device it will be wiped off the usb.
the guide will take you through most of the configuration
I have only tested this on a closed network I have not tested over 2 seperate networks if someone can do that with a set-up guide e.g. portforwarding etc on the router that would be helpful
The message log does fill up quickly so be sure to regularly purge the messages
remote wipe isn't working correctly at this stage.
