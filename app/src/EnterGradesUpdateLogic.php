<?php
try {
    /*Get DB connection*/
    require_once "../src/DBController.php";

    if (isset($_POST['submit'])) { //checks if submit var is set
        $currentDirectory = realpath(__DIR__ . DIRECTORY_SEPARATOR . '..');//get root directory
        $uploadDirectory = "\uploads\\";

        // INPUT VALIDATION: verify a file was actually uploaded & no upload error occurred
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception("An error occurred. Please try again.");
        }

        //get info about the file
        $filename = $_FILES['file']['name'];
        $filetmp  = $_FILES['file']['tmp_name'];
        $filesize = filesize($filetmp); // added for HW2 Task 2 input validation below
 
        // INPUT VALIDATION: check that the file was legitimately uploaded via HTTP POST
        // (guards against local file inclusion attacks)
        if (!is_uploaded_file($filetmp)) {
            throw new Exception("An error occurred. Please try again.");
        }
 
        // INPUT VALIDATION: enforce a max file size (1 MB)
        $maxFileSizeBytes = 1048576;
        if ($filesize > $maxFileSizeBytes) {
            throw new Exception("An error occurred. Please try again.");
        }
 
        $path = pathinfo($filename);
 
        // INPUT VALIDATION: verify the file extension is .csv
        if (!isset($path['extension']) || strtolower($path['extension']) !== 'csv') {
            throw new Exception("An error occurred. Please try again.");
        }
 
        // INPUT VALIDATION: verify the actual MIME type of the uploaded file matches
        // a plain-text/csv type. Checking only the extension allows an attacker to
        // rename a PHP file to grades.csv and upload it for code injection.
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($filetmp);
        $allowedMimeTypes = ['text/plain', 'text/csv', 'application/csv', 'application/vnd.ms-excel'];
        if (!in_array($mimeType, $allowedMimeTypes, true)) {
            throw new Exception("An error occurred. Please try again.");
        }

 
        //create the upload path with the original filename
        $uploadPath = $currentDirectory . $uploadDirectory . basename($filename);

        //copy file to uploads folder
        copy($filetmp, $uploadPath);

        //prepare vars to insert data into database
        $handle = fopen(($_FILES['file']['tmp_name']), "r"); //sets a read-only pointer at beginning of file
        $crn = $_POST['crn']; //grabs CRN from form


        // INPUT VALIDATION: CRN must be a non-empty numeric string
        if (empty($crn) || !ctype_digit(strval($crn))) {
            fclose($handle);
            throw new Exception("An error occurred. Please try again.");
        }
 
        //insert data into the database from csv
        while (($data = fgetcsv($handle, 9001, ",", escape: "")) !== FALSE) { //iterate through csv
 
            // INPUT VALIDATION: every CSV row must have exactly two columns
            if (count($data) !== 2) {
                fclose($handle);
                throw new Exception("An error occurred. Please try again.");
            }
 
            $userId = trim($data[0]);
            $grade  = trim($data[1]);
 
            // INPUT VALIDATION: USER_ID must be a non-empty numeric string
            if (empty($userId) || !ctype_digit($userId)) {
                fclose($handle);
                throw new Exception("An error occurred. Please try again.");
            }
 
            // INPUT VALIDATION: GRADE must be one of the allowed letter grades
            $allowedGrades = ['A', 'B', 'C', 'D', 'F'];
            if (!in_array(strtoupper($grade), $allowedGrades, true)) {
                fclose($handle);
                throw new Exception("An error occurred. Please try again.");
            }
 
            // Use a prepared statement to prevent SQL injection.
            // The original code used escapeString only on the CRN and still built the
            // query with string interpolation, leaving $data[0] and $data[1] unsanitized.
            $stmt = $db->prepare("INSERT INTO Grade VALUES (:crn, :userId, :grade)");
            $stmt->bindValue(':crn',    $crn,                 SQLITE3_INTEGER);
            $stmt->bindValue(':userId', $userId,              SQLITE3_INTEGER);
            $stmt->bindValue(':grade',  strtoupper($grade),   SQLITE3_TEXT);
            $stmt->execute();
        }
 
        $db->backup($db, "temp", $GLOBALS['dbPath']);
        fclose($handle);
 
        header("Location: ../public/dashboard.php");
    }
    else{throw new Exception("An error occurred. Please try again.");}
}
catch(Exception $e)
{
    // INPUT VALIDATION: return a generic error message rather than exposing internal
    // details (file paths, stack traces, variable dumps) to the client.
    include_once "ErrorHeader.php";
    echo htmlspecialchars("An error occurred. Please try again.", ENT_QUOTES | ENT_HTML5, 'UTF-8');
}