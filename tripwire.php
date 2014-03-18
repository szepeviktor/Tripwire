<?php

/*
 *  Tripwire
 *  Luke Stevenson <www.lucanos.com>
 *  and Daniel Walker <polyesterhat@gmail.com>
 *
 *  This is a PHP script which will scan files within a directory (including
 *    sub-directories), calculate their MD5 Hashes and then compare them against
 *    a log of the results from the previous execution to determine any files
 *    which have been added, deleted or modified during that period.
 *
 *  Within the Configuration Settings, exclusions can be set for any files/folders
 *    which should not be checked.
 *
 *  For best results, this file should be triggered by a cron job at regular intervals.
 *    Also, be sure to add your email address to the Configuration Settings to ensure
 *    that you recieve the notifications.
 *
 */

class Tripwire
{
    protected $config;

    /**
     * a place to keep the messages before they all get echoed
     * 
     * @var array
     */
    protected $messages_buffer = array();

    public function __construct()
    {
        $this->load_settings('tripwire_config.ini');

        // make a debug shortcut
        $this->DEBUG = $this->config['debug'];

        // start checking the supplied dirs
        $this->check_paths();

        var_dump($this->messages_buffer);
    }


    /**
     * this is the real meat and potatoes of Tripwire
     * 1. first get paths from config file
     * 2. traverse them and check for differences in the 
     *    date modified to what we have on file
     * 3.
     * 
     * @since   2014-03-17
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @return  void
     */
    protected function check_paths()
    {
        $paths = $this->config['paths'];

        if (!is_array($paths))
        {
            $this->add_message('In config, paths should be an array');
            $paths = (array) $paths;
        }

        // If no Directory Specified, Default to the Root 
        // of the Site the script is executed under
        if (empty($paths))
        {
            $this->add_message('Paths is empty in the config - it shouldn\'t be');
            $paths = (array) $_SERVER['DOCUMENT_ROOT'];
        }

        foreach ($paths as $index => $path)
        {
            // If last character is a slash, strip it off the end
            if( substr( $path , -1 ) == '/' )
            {
                $path = substr( $path , 0 , -1 );
            }

            // If the supplied variable is not a Directory, terminate
            if (!is_dir($path))
            {
                $this->add_message("Directory '{$path}' does not exist.");

                // go to next path
                continue;
            }

            $this->add_message("Checking directory '{$path}'");

            $this->check_path($path);

            return $temp;
        }
    }


    /**
     * check just one path from the config file
     * this is a recursive function
     *
     * @since   2014-03-17
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @param   string     $path the path to the directory
     * @return  void
     */
    protected function check_path($path = '')
    {

    }


    /**
     * to maintain a buffer of messages
     * this method will simply push a new string onto 
     * the messages array
     *
     * @since   2014-03-17
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @param   string $message a new message
     * @return  void
     */
    protected function add_message($message)
    {
        array_push($this->messages_buffer, $message);
    }


    /**
     * just send an email using the config settings
     * this $this->config
     *
     * @since   2014-03-17
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @param   string     $message the body of the email
     * @return  boolean
     */
    protected function email_user($message)
    {
        // Prepare the recipients
        $to = implode( ', ' , $this->config['email']['to'] );

        // Send it
        $result = mail(
            $this->config['email']['to'],
            $this->config['title'],
            $message
        );

        return $result;
    }


    /**
     * find config file and parse using built in in parser
     * load the settings into class variable
     *
     * @since   2014-03-17
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @param   string $file_name the name of the config file for tripwire
     * @return  void
     */
    protected function load_settings($file_name)
    {
        $this->config = parse_ini_file($file_name);
    }
}

// Start the Instance
$t = new Tripwire();

