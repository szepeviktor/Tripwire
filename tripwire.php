<?php

/*
 *  Tripwire
 *  Luke Stevenson <www.lucanos.com>
 *  and Daniel Walker <polyesterhat@gmail.com>
 *
 *  This is a PHP script which will scan files within a directory (including
 *    sub-directories), calculate their MD5 Hashes and then compare them against
 *    a log of the results from the previous execution to determine any files
 *    which have been added, deleted || modified during that period.
 *
 *  Within the Configuration Settings, exclusions can be set for any files/folders
 *    which should not be checked.
 *
 *  For best results, this file should be triggered by a cron job at regular intervals.
 *    Also, be sure to add your email address to the Configuration Settings to ensure
 *    that you recieve the notifications.
 *
 * For the email template, I'm using:
 * leemunroe.github.io/html-email-template/email.html
 * Twig is used to compile the template
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


    /**
     * a place to keep strings
     * regarding the files being processed
     * before outputting for user
     * this is for display, not function
     *
     * @var array
     */
    protected $files_buffer = array();


    /**
     * arrays to house comparison results
     * @var array
     */
    protected $files_new = array();
    protected $files_modified = array();
    protected $files_deleted = array();


    /**
     * flag to track whether there are differences between 
     * this run and the last run
     * @var boolean
     */
    protected $there_were_differences = FALSE;


    /**
     * a place to store md5s of files
     * @var array
     */
    protected $listing_now = array();
    protected $listing_last = array();


    /**
     * html for the report
     * built out in method: prepare_report()
     * @var string
     */
    protected $report = '';

    public function __construct()
    {
        $this->load_settings('tripwire_config.ini');

        // make a debug shortcut
        $this->DEBUG = $this->config['debug'];

        // start checking the supplied dirs
        $this->check_paths();

        $this->run_comparisons();

        $this->save_md5_file();

        $this->prepare_report();

        // @FIXME these two are also missing: var_dump($this->messages_buffer);
        // var_dump($this->files_buffer);
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

        // start a clean copy of the listing
        // this is updated in check_path()
        $this->listing_now = array();

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

            $this->check_path($path);
        }
    }


    /**
     * check just one path from the config file
     * this is a recursive function
     *
     * @since   2014-03-17
     * @author  Luke Stevenson <www.lucanos.com>
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @param   string     $path the path to the directory
     * @return  void
     */
    protected function check_path($path = '')
    {
        $this->add_message("Checking directory '{$path}'");

        $d = dir($path);

        // Loop through the files
        while (FALSE !== ($entry = $d->read()))
        {
            // Full Entry (including Directory)
            $entry_full = $path . '/' . $entry;

            // Symbolic Link - Excluded
            if (is_link($entry))
            {
                // add symlink to buffer
                $this->add_file($path, $entry . ' <- symlink');
                continue;
            }

            // determine whether this file should be excluded
            // based on file name || extension
            $exclude_file = in_array($entry , $this->config['files']) || in_array($entry_full , $this->config['files']);

            $exclude_extension = in_array(pathinfo($entry , PATHINFO_EXTENSION) , $this->config['extensions']);

            // Excluded File/Folder
            if ($exclude_file || $exclude_extension)
            {
                $this->add_file($path, $entry . ' <- excluded');
                continue;
            }

            if (is_dir($entry_full))
            {
                // label this file for the output listing
                $this->add_file($path, $entry . ' <- directory');

                // Recurse
                $this->check_path($entry_full);
            }
            else
            {
                // a file
                // check date
                // if different date check md5
                $md5 = @md5_file( $entry_full );
                $this->add_file($path, $entry);

                if (!$md5)
                {
                    $this->add_message("Could not md5: {$entry_full}");
                    file_put_contents($this->config['unreadable_list'] ,  "{$entry_full} - Unreadable\n" , FILE_APPEND);
                }
                else
                {
                    $this->listing_now[$entry_full] = $md5;
                }
            }
        }

        $d->close();
    }


    /**
     * opens the file used last time and
     * compares line by line with the latest results from check paths
     *
     * @since   2014-03-18
     * @author  Luke Stevenson <www.lucanos.com>
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @todo    make the comparisons faster
     * @return  void
     */
    protected function run_comparisons()
    {
        $this->listing_last = array();

        if (file_exists($this->config['md5_file']))
        {
            $temp = file_get_contents($this->config['md5_file']);

            $this->listing_last = (array)json_decode($temp);
        }

        // kept Luke's old logic here
        // there are probably faster ways to do this
        // Perform Comparisons
        $keys_now = array_keys($this->listing_now);
        $keys_last = array_keys($this->listing_last);
        // New Files = Files in $now, but not in $last
        $this->files_new = array_diff($keys_now, $keys_last);

        // Deleted Files = Files in $last, but not in $now
        $this->files_deleted = array_diff($keys_last, $keys_now);

        // Changed Files = Files in $last and $now, but with Different MD5 Hashes
        $this->files_modified = array_diff_assoc(
            array_flip(array_intersect_key($this->listing_last, $this->listing_now)),
            array_flip(array_intersect_key($this->listing_now, $this->listing_last))
        );

        $this->there_were_differences = count($this->files_new) || count($this->files_modified) || count($this->files_deleted);
    }


    /**
     * simply save the new listing into the file
     *
     * @since   2014-03-18
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @return  void
     */
    protected function save_md5_file()
    {
        // write the file if there wasn't already a file
        // || there were differences
        if (empty($this->listing_last) || $this->there_were_differences)
        {
            // json encode is slightly faster than serialize since it 
            // doesn't have to insert string lengths
            file_put_contents($this->config['md5_file'], json_encode($this->listing_now));
        }
    }


    /**
     * generate all html to send to the user
     * regarding the findings of the tripwire run
     * this will include new files, modifications, deletions
     * and the time
     *
     * @since   2014-03-18
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @author  Luke Stevenson <www.lucanos.com>
     * @return  void
     */
    protected function prepare_report()
    {
        $vars = array(
            'AF' => $this->files_new,
            'MF' => $this->files_modified,
            'DF' => $this->files_deleted,
            'total' => 0,
            'title' => 'Tripwire - no changes',
            'heading' => 'Tripwire has not detected any changes',
        );

        // If there was a Filelist from the last run to
        // compare against, and changes have occurred then,
        // Prepare Report
        if (empty($this->listing_last))
        {
            // First Run
            $this->add_message('There was no previous listings - this was a first run.');

            $vars['total'] = count($this->files_new);
            $vars['title'] = 'Tripwire - First Run';
            $vars['heading'] = 'Tripwire has made it\'s first pass of your files';
        }
        elseif ($this->there_were_differences)
        {
            $this->add_message('There was a previous listing and there are differences.');

            // Changes Detected

            $vars['total'] = count($this->files_new) + count($this->files_deleted) + count($this->files_modified);
            $vars['title'] = 'Tripwire - Changes Detected';
            $vars['heading'] = 'Tripwire has detected a number of changes:';
        }
        else
        {
            $this->add_message('There were no differences.');

            // nothing to do...
            return;
        }

        // make email subject
        $subject = str_replace( '{{X}}' , $vars['total'] , $this->config['subject'] );

        // Compile the email template with Twig
        require_once 'include/twig/lib/Twig/Autoloader.php';
        Twig_Autoloader::register();

        $loader = new Twig_Loader_Filesystem( dirname(__FILE__) . '/views' );
        $twig = new Twig_Environment($loader);

        $template = $twig->loadTemplate('email_template.html');

        $body = $template->render($vars);

        $this->email_user($subject, $body);

        if ($this->DEBUG)
        {
            echo $body;
        }

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
     * to keep a running list of files
     *
     * @since  2014-03-18
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @param   string $path the path to use
     * @param   string $file a new file
     * @return  void
     */
    protected function add_file($path ='', $file = '')
    {
        if (!array_key_exists($path, $this->files_buffer))
        {
            $this->files_buffer[$path] = array();
        }

        array_push($this->files_buffer[$path], $file);
    }


    /**
     * just send an email using the config settings
     * this $this->config
     *
     * @since   2014-03-17
     * @author  Daniel.Walker <polyesterhat@gmail.com>
     * @param   string     $subject of the email
     * @param   string     $body of the email
     * @return  boolean
     */
    protected function email_user($subject, $body)
    {
        $result = FALSE;

        if ($this->config['send_email'])
        {
            $headers = "MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Disposition: inline";

            // Prepare the recipients
            $to = implode(', ' , $this->config['to']);

// @FIXME phpmailer is not yet used, only HTML email
            // Send it
            $result = mail(
                $to,
                $subject,
                $body,
                $headers
            );
        }

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
new Tripwire();

