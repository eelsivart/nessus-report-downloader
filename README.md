Name: Nessus Report Downloader
Author: Travis Lee

Version: 1.0
Last Updated: 3/12/2014

Description:  
Interactive script that connects to a specified Nessus server using the
Nessus REST API to automate mass report downloads. It has the ability to download
multiple or all reports/file types/chapters and save them to a folder of
your choosing. This has been tested with Nessus 5.2.5 and *should* work with
Nessus 5+, YMMV.

File types include: .nessus v2, HTML, PDF, CSV, and NBE. 

Chapter types include: Vulnerabilities By Plugin, Vulnerabilities By Host, 
Hosts Summary (Executive), Suggested Remediations, Compliance Check (Executive), 
and Compliance Check.

A windows executable is also available that was created with OCRA.


Requires: nokogiri (gem install nokogiri)

Usage: ruby ./nessus-report-downloader.rb
Windows EXE Usage: .\nessus-report-downloader-1.0.exe



