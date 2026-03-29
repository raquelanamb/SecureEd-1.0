<?php
try {
    /*Get DB connection*/
    require_once "../src/DBController.php";

    /*Get information from the search (post) request*/
    $acctype = $_POST['acctype'];
    $fname = $_POST['fname'];
    $lname = $_POST['lname'];
    $dob = $_POST['dob'];
    $email = $_POST['email'];
    $studentyear = $_POST['studentyear'];
    $facultyrank = $_POST['facultyrank'];

    if($acctype==null)
    {throw new Exception("input did not exist");}

    //handle blank values
    if ($fname === "") {
        $fname = "defaultvalue!";
    }
    if ($lname === "") {
        $lname = "defaultvalue!";
    }
    if ($dob === "") {
        $dob = "defaultvalue!";
    }
    if ($email === "") {
        $email = "defaultvalue!";
    }
    if ($studentyear === "") {
        $studentyear = "defaultvalue!";
    }
    if ($facultyrank === "") {
        $facultyrank = "defaultvalue!";
    }


    //determine account type
    if ($acctype == "Student") {
        //send back student type search results

        $query = "SELECT * FROM User WHERE AccType=3 AND 
            (Fname LIKE :fname OR :fname = 'defaultvalue!') AND
            (Lname LIKE :lname OR :lname = 'defaultvalue!') AND
            (DOB LIKE :dob OR :dob = 'defaultvalue!') AND
            (Email LIKE :email OR :email = 'defaultvalue!') AND
            (Year LIKE :studentyear OR :studentyear = 'defaultvalue!')";
        $stmt = $db->prepare($query); //prevents SQL injection by escaping SQLite characters
        $stmt->bindParam(':studentyear', $studentyear, SQLITE3_INTEGER);
        $stmt->bindParam(':fname', $fname, SQLITE3_TEXT);
        $stmt->bindParam(':lname', $lname, SQLITE3_TEXT);
        $stmt->bindParam(':dob', $dob, SQLITE3_TEXT);
        $stmt->bindParam(':email', $email, SQLITE3_TEXT);
        $results = $stmt->execute();
    }
    else if ($acctype == "Faculty") {
        //send back faculty type search results

        $query = "SELECT * FROM User WHERE AccType=2 AND 
            (Fname LIKE :fname OR :fname = 'defaultvalue!') AND
            (Lname LIKE :lname OR :lname = 'defaultvalue!') AND
            (DOB LIKE :dob OR :dob = 'defaultvalue!') AND
            (Email LIKE :email OR :email = 'defaultvalue!') AND
            (Rank LIKE :facultyrank OR :facultyrank = 'defaultvalue!')";
        $stmt = $db->prepare($query); //prevents SQL injection by escaping SQLite characters
        $stmt->bindParam(':facultyrank', $facultyrank, SQLITE3_TEXT);
        $stmt->bindParam(':fname', $fname, SQLITE3_TEXT);
        $stmt->bindParam(':lname', $lname, SQLITE3_TEXT);
        $stmt->bindParam(':dob', $dob, SQLITE3_TEXT);
        $stmt->bindParam(':email', $email, SQLITE3_TEXT);
        $results = $stmt->execute();
    }
    else {
        //send back a general search (may change to exclude admins)

        $query = "SELECT * FROM User WHERE
            (Fname LIKE :fname OR :fname = 'defaultvalue!') AND
            (Lname LIKE :lname OR :lname = 'defaultvalue!') AND
            (DOB LIKE :dob OR :dob = 'defaultvalue!') AND
            (Email LIKE :email OR :email = 'defaultvalue!') AND
            (Rank LIKE :facultyrank OR :facultyrank = 'defaultvalue!')";
        $stmt = $db->prepare($query); //prevents SQL injection by escaping SQLite characters
        $stmt->bindParam(':fname', $fname, SQLITE3_TEXT);
        $stmt->bindParam(':lname', $lname, SQLITE3_TEXT);
        $stmt->bindParam(':dob', $dob, SQLITE3_TEXT);
        $stmt->bindParam(':email', $email, SQLITE3_TEXT);
        $stmt->bindParam(':facultyrank', $facultyrank, SQLITE3_TEXT);
        $results = $stmt->execute();
    }

    global $jsonArray;

    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        // HW2 TASK 1 pt1:
        // XSS MITIGATION: sanitize all string fields before returning them to the client.
        // htmlspecialchars() converts special HTML characters (e.g. <, >, ", &) into their
        // HTML entity equivalents, preventing injected scripts or markup from being
        // interpreted by the browser.
        $sanitizedRow = array();
        foreach ($row as $key => $value) {
            if (is_string($value)) {
                $sanitizedRow[$key] = htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            } else {
                $sanitizedRow[$key] = $value;
            }
        }
        $jsonArray[] = $sanitizedRow;
    }

    echo json_encode($jsonArray);
}
catch(Exception $e)
{
    // HW2 Task 1 pt2: 
    // returning a generic error message instead of exposing
    // internal exception details, stack traces, or variable dumps to the client.
    http_response_code(500);
    echo json_encode(array("error" => "An error occurred. Please try again."));
}


//note: since no changes happen to the database, it is not backed up on this page
?>