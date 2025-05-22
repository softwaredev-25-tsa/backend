# The Backend
The backend for Terraining is built entirely in Kotlin with the Ktor library to handle HTTP requests and Websocket connections. It has the role of managing accounts and the exchange of files between the sender and runner clients. The most important file, which is used for routing, is the `Routing.kt` file located in `/src/main/kotlin/gcittsasd/api/plugins/Routing.kt`.

## The accounts system
The accounts are stored and managed with Airtable, an easy to interact database that stores items in a basic excel spreadsheet-like system. It is interacted with using simple REST API methods to make, get, update, and delete records.

## The encryption
The encryption is a huge part of the backend, keeping the entire system secure. We use basic RSA with some of our own modifications for maximum security and efficiency. The server has a public key and private key for the encryption. Clients can request to see the public key using the `/key` route. Messages are encrypted with the public key that the server can then decrypt using its private key.
#### The problem we encountered with this
RSA encryption makes the message unreadable to anyone but the server; however, if an attacker intercepts a request and resends it to receive another response of the same kind. For example, the user would login and the attacker would try to use the same login request to get their own response.
#### The solution we found
By adding a unique identifier string to the end of the plaintext. It modifies the entire encrypted text and if an attacker were to resend it, the server would see that someone already used that identifier and block the request.

## The exchange system
The file exchange system is more simple and just sends the file to the best gpu based on an algorithm. It sends the file and waits for a response to give the sender client.

## The VirusTotal scanning
To prevent malicous files from being sent, not only is the file run in a docker container environment, but the server also uses the VirusTotal API to scan it for malware. VirusTotal is very well known and good at finding viruses and other unwanted underlying programs in a file.
