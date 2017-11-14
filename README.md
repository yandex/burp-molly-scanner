# Burp-molly-scanner

# Overview
The main goal of Burp-molly-scanner is to extend Burp and turn it into headless active scanner.

# Usage
* Build fat jar with Maven
* Rewrite burp_molly_config.json
* Put path to config in MOLLY_CONFIG Environment variable
* Run Burp Suite in console `java -jar burpsuite_pro.jar`
* Add Plugin in Extender Tab (once)
* Run scanner in headless mode (see run.sh)
* Parse resulting XML report
* Integrate it to your security pipeline

# Contributing
Contributions to Burp-molly-scanner are always welcome! You can help us in different ways:
  * Open an issue with suggestions for improvements and errors you're facing;
  * Fork this repository and submit a pull request;
  * Improve the documentation.
