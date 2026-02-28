<?php
try {
    /*Get DB connection*/
    require_once "../src/DBController.php";

    # TASK 1: Applying input validation
    /*Get information from the post request*/
    $myusername = $_POST['username'] ?? ''; # default to empty string if not provided
    $mypassword = $_POST['password'] ?? ''; # default to empty string if not provided

    # moved up for logical flow, normalization should happen before validation:
    $myusername = strtolower($myusername); //makes username noncase-sensitive

    // email validation:
    if (!preg_match("/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/", $myusername)) {
        header("Location: ../public/index.php?login=fail");
        exit();
    }

    // password validation:
    if (!preg_match("/^(?=.*[A-Z])(?=.*[0-9])[A-Za-z0-9]{8,16}$/", $mypassword)) {
        header("Location: ../public/index.php?login=fail");
        exit();
    }

    //convert password to 80 byte hash using ripemd256 before comparing
    $hashpassword = hash('ripemd256', $mypassword);

    #if($myusername==null)
    #{throw new Exception("input did not exist");}  # no longer needed due to null coalescing above

    global $acctype;


    # TASK 2: Mitigate the SQLi vulnerability

    //query for count
    $stmt = $db->prepare("SELECT COUNT(*) as count FROM User WHERE Email=:email AND (Password=:pass OR Password=:hash)");
    $stmt->bindValue(':email', $myusername,   SQLITE3_TEXT);
    $stmt->bindValue(':pass',  $mypassword,   SQLITE3_TEXT);
    $stmt->bindValue(':hash',  $hashpassword, SQLITE3_TEXT);
    $countResult = $stmt->execute();
    $count = $countResult->fetchArray(SQLITE3_ASSOC)['count'];

    //query for the row(s)
    $stmt2 = $db->prepare("SELECT * FROM User WHERE Email=:email AND (Password=:pass OR Password=:hash)");
    $stmt2->bindValue(':email', $myusername,   SQLITE3_TEXT);
    $stmt2->bindValue(':pass',  $mypassword,   SQLITE3_TEXT);
    $stmt2->bindValue(':hash',  $hashpassword, SQLITE3_TEXT);
    $results = $stmt2->execute();

    if ($results !== false) //query failed check
    {
        if (($userinfo = $results->fetchArray()) !== (null || false)) //checks if rows exist
        {
            // users or user found
            $error = false;

            $acctype = $userinfo[2];
        } else {
            // user was not found
            $error = true;

        }
    } else {
        //query failed
        $error = true;

    }

    //determine if an account that met the credentials was found
    if ($count >= 1 && !$error) {
        //login success

        if (isset($_SESSION)) {
            //a session already existed
            session_destroy();
            session_start();
            $_SESSION['email'] = $myusername;
            $_SESSION['acctype'] = $acctype;
        } else {
            //a session did not exist
            session_start();
            $_SESSION['email'] = $myusername;
            $_SESSION['acctype'] = $acctype;
        }
        //redirect
        header("Location: ../public/dashboard.php");
    } else {
        //login fail
        header("Location: ../public/index.php?login=fail");
    }
//note: since the database is not changed, it is not backed up
}

catch(Exception $e)
{
    error_log($e->getMessage() . "\n" . $e->getTraceAsString()); // logs server-side only
    header("Location: ../public/index.php?login=fail");
    exit();
}




