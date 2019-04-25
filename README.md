# Cisco Email Health Checker (EHC)

This is sample code for our prototype of the EHC. Created by Hakan Nohre and Christopher van der Made.

Ehc.py contains the brains of the process.

## Solution components

* EHC checks which licenses have been installed and how long they are still valid.
* EHC checks if all the features are enabled that the customer has the right to from a licensing perspective.
* EHC checks many best practice values like: Spam engines scan sizes, amount of listeners, and many more to come.
* EHC checks that Host Access Table for discrepancies. 
* EHC also checks the DNS records of the customer’s domain, to check if DMARC and SPF are correctly enabled and if indeed only the approved mail servers can receive email (also with reverse DNS). Many more DNS based checks will be added (DANE etc.).
## Roadmap

* Adding more email config health checks (from 25 -> 300)
* Adding more DNS based health checks (DANE etc.)
* Making checks more customizable (enable, disable, limits)
* Adding links to corrective actions (in config guide) and explanations for each check
* Kick start Cisco Domain Protection PoV for customers with no DMARC.

