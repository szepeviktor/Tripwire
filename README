
#Tripwire

A PHP script, designed to be run by a cron job, which detects files which have been added, deleted or modified since the previous execution of the script. **Sends emails** with a summary of changes. Great for detecting malicious activity (hacking, unauthorised access other hacker actions)


##Uses:

Wordpress virus guard. I have seen a virus which will rewrite your php files [documented here](http://wordpress.org/support/topic/virus-appending-base64-code-to-all-php-files).

Malicious Uploads. This script will tell you *anytime* a file is added/removed/modified. This can get annoying, but between the settings available in Tripwire, and your own email filters, you should be able to come up with a nice solution.


##Installation

Download this repo as a zip and install on your server, or use a git pull. 

*In terminal run:*

    cd ~

    git clone https://github.com/polyesterhat/Tripwire.git

    cd Tripwire

    cp tripwire_config.sample.ini tripwire_config.ini


That last command will make an untracked config file (which is good). Now, configure the `tripwire_config.ini` file ([ini file info here](http://us3.php.net/parse_ini_file)). At least put in your own email address and customize the paths array so the script knows which directories to watch.

**Set up the Crontab (cronjob)**

    crontab -e

This will open a VI editor. And paste in: 

    */15 * * * *   php /path/to/Tripwire/tripwire.php

If you don't know how to use VI, just remember, hit the "i" key to start typing or pasting, and then hit esc, ctrl+; to enter command mode, and once in command mode type 'wq' and hit enter. This will save and exit.

15 is how the number of minutes tripwire should wait, if you want 5, put a 5 instead of a 15. [More information here](http://www.linuxmanpages.com/man5/crontab.5.php).

